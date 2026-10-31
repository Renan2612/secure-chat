// Cofre do navegador (B-D2): o equivalente ao keystore + trust store do
// ws-client, selado no IndexedDB. Três registros por usuário, cada um no
// MESMO formato do keystore.js (sealJson: PBKDF2-SHA-256 >= 600 000 + AES-GCM,
// cabeçalho no AAD) sob a senha de cifragem, DISTINTA da senha de login:
//   identity  { v, userId, identity: {ecdhPub, ecdsaPub, ecdhPriv, ecdsaPriv}, trustStoreId }
//             gravado só na criação
//   state     { v, vaultId, roomKeys, rooms, roomNames, kicked } (muda com o uso)
//   trust     trust store (shared/e2ee/trust.js) com o id do cofre (P1 da 4b-2)
// Separar a identidade do estado faz as privadas (PKCS#8) existirem em claro
// na memória só durante a criação e o desbloqueio: depois, só como CryptoKey
// não extraível. O state e o trust levam o id do cofre (vaultId = o
// trustStoreId da identidade): um registro de OUTRO cofre do mesmo navegador,
// selado com a mesma senha, é recusado (achado da revisão). Limite: quem
// escreve no IndexedDB pode repor uma cópia ANTIGA dos três registros juntos
// (rollback); detectar isso exigiria um contador fora do navegador (docs/07).
// Sem recuperação: perdeu a senha de cifragem ou os dados do
// navegador, perdeu as chaves (avisado na criação).
import e2ee from "./e2ee.js";
import { importIdentityNonExtractable } from "./browser.js";
import { idbDelete, idbGet, idbPutMany } from "./idb.js";

const RECORDS = ["identity", "state", "trust"];
const keyOf = (userId, record) => `${userId}:${record}`;

export class VaultError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "VaultError";
    this.code = code;
  }
}

const emptyState = (vaultId) => ({ v: 1, vaultId, roomKeys: {}, rooms: {}, roomNames: {}, kicked: {} });
const newId = () => e2ee.encoding.toB64url(e2ee.primitives.randomBytes(16));

export const hasVault = async (userId) => (await idbGet(keyOf(userId, "identity"))) !== undefined;

export const deleteVault = (userId) => idbDelete(RECORDS.map((r) => keyOf(userId, r)));

// O cofre aberto. A senha de cifragem fica na memória até o lock (é preciso
// selar de novo a cada mudança de estado); lock() apaga tudo.
// Mudanças por FUNÇÃO (updateState(s => próximo), updateTrust(t => próximo)),
// uma de cada vez, sempre sobre o último estado gravado (achado da
// revisão): duas operações simultâneas que partissem da mesma cópia
// apagariam uma a outra — e o que se perde são pinos de segurança (versão
// fixada, maior seq do nome, chave fixada de um contato).
const openedVault = ({ userId, vaultId, passphrase, identity, pub, state, trust, trustReset }) => {
  let secret = passphrase;
  let queue = Promise.resolve();
  // Enfileira; o updater recebe o valor atual e devolve o próximo (devolver
  // o mesmo objeto = nada a gravar).
  const serially = (field, record, updater) => {
    const run = queue.then(async () => {
      if (vault.locked) throw new VaultError("LOCKED", "cofre bloqueado");
      const current = vault[field];
      let next = await updater(current);
      if (next === current) return current;
      if (field === "state") next = { ...next, vaultId }; // sempre amarrado a ESTE cofre
      // Grava ANTES de trocar a memória: se falhar, nada fica "valendo só nesta aba".
      await idbPutMany([[keyOf(userId, record), await e2ee.sealJson(secret, next)]]);
      // Bloqueado durante a gravação: não devolve o estado à memória.
      if (vault.locked) throw new VaultError("LOCKED", "cofre bloqueado");
      vault[field] = next;
      return next;
    });
    queue = run.catch(() => {});
    return run;
  };
  const vault = {
    userId,
    identity,
    pub,
    state,
    trust,
    trustReset,
    locked: false,
    updateState: (updater) => serially("state", "state", updater),
    updateTrust: (updater) => serially("trust", "trust", updater),
    lock() {
      secret = null;
      Object.assign(vault, { identity: null, state: null, trust: null, locked: true });
    },
  };
  return vault;
};

export const createVault = async ({ userId, passphrase, loginPassword }) => {
  if (passphrase === loginPassword) {
    throw new VaultError("SAME_AS_LOGIN", "a senha de cifragem precisa ser diferente da senha de login");
  }
  if (await hasVault(userId)) throw new VaultError("EXISTS", "já existe um cofre para esta conta neste navegador");
  const fresh = await e2ee.generateIdentity();
  const exported = await e2ee.exportIdentity(fresh);
  const trustStoreId = newId();
  // sealJson valida a senha (mínimo de caracteres) antes de gravar qualquer coisa.
  const sealedIdentity = await e2ee.sealJson(passphrase, { v: 1, userId, identity: exported, trustStoreId });
  const state = emptyState(trustStoreId);
  const trust = { ...e2ee.emptyTrustStore(), id: trustStoreId };
  await idbPutMany([
    [keyOf(userId, "identity"), sealedIdentity],
    [keyOf(userId, "state"), await e2ee.sealJson(passphrase, state)],
    [keyOf(userId, "trust"), await e2ee.sealJson(passphrase, trust)],
  ]);
  const { ecdhPub, ecdsaPub } = exported;
  return openedVault({ userId, vaultId: trustStoreId, passphrase, identity: await importIdentityNonExtractable(exported), pub: { ecdhPub, ecdsaPub }, state, trust, trustReset: false });
};

// Senha errada e registro adulterado são indistinguíveis (BAD_PASSPHRASE,
// do keystore.js); nada é sobrescrito numa falha.
export const unlockVault = async ({ userId, passphrase }) => {
  const sealedIdentity = await idbGet(keyOf(userId, "identity"));
  if (!sealedIdentity) throw new VaultError("NO_VAULT", "não há cofre para esta conta neste navegador");
  const opened = await e2ee.openJson(passphrase, sealedIdentity);
  if (opened.userId !== userId) throw new VaultError("WRONG_USER", "este cofre é de outra conta");
  const vaultId = opened.trustStoreId;
  const sealedState = await idbGet(keyOf(userId, "state"));
  let state = emptyState(vaultId);
  if (sealedState) {
    // O id é conferido no registro DECIFRADO, antes de mesclar com os
    // padrões: um registro sem vaultId não herda o deste cofre (revisão).
    const raw = await e2ee.openJson(passphrase, sealedState);
    if (raw?.vaultId !== vaultId) {
      throw new VaultError("STATE_MISMATCH", "o estado das salas deste navegador não pertence a este cofre; nada foi alterado");
    }
    state = { ...state, ...raw };
  }
  const sealedTrust = await idbGet(keyOf(userId, "trust"));
  let trust;
  let trustReset = false;
  if (sealedTrust) {
    trust = await e2ee.openJson(passphrase, sealedTrust);
    if (trust.id !== vaultId) {
      throw new VaultError("TRUST_MISMATCH", "o trust store deste navegador não pertence a este cofre; nada foi alterado");
    }
  } else {
    // P1 da 4b-2: trust store sumiu com o cofre ainda lá → TOFU reiniciado,
    // com aviso (quem chama mostra: todos voltam a "não verificado").
    trust = { ...e2ee.emptyTrustStore(), id: vaultId };
    await idbPutMany([[keyOf(userId, "trust"), await e2ee.sealJson(passphrase, trust)]]);
    trustReset = true;
  }
  const { ecdhPub, ecdsaPub } = opened.identity;
  const identity = await importIdentityNonExtractable(opened.identity);
  return openedVault({ userId, vaultId, passphrase, identity, pub: { ecdhPub, ecdsaPub }, state, trust, trustReset });
};
