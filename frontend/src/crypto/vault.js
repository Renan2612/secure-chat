// Cofre do navegador (B-D2): o equivalente ao keystore + trust store do
// ws-client, selado no IndexedDB. Três registros por usuário, cada um no
// MESMO formato do keystore.js (sealJson: PBKDF2-SHA-256 >= 600 000 + AES-GCM,
// cabeçalho no AAD) sob a senha de cifragem, DISTINTA da senha de login:
//   identity  { v, userId, identity: {ecdhPub, ecdsaPub, ecdhPriv, ecdsaPriv}, trustStoreId }
//             gravado só na criação
//   state     { v, roomKeys, rooms, roomNames, kicked } (muda com o uso)
//   trust     trust store (shared/e2ee/trust.js) com o id do cofre (P1 da 4b-2)
// Separar a identidade do estado faz as privadas (PKCS#8) existirem em claro
// na memória só durante a criação e o desbloqueio: depois, só como CryptoKey
// não extraível. Sem recuperação: perdeu a senha de cifragem ou os dados do
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

const emptyState = () => ({ v: 1, roomKeys: {}, rooms: {}, roomNames: {}, kicked: {} });
const newId = () => e2ee.encoding.toB64url(e2ee.primitives.randomBytes(16));

export const hasVault = async (userId) => (await idbGet(keyOf(userId, "identity"))) !== undefined;

export const deleteVault = (userId) => idbDelete(RECORDS.map((r) => keyOf(userId, r)));

// O cofre aberto. A senha de cifragem fica na memória até o lock (é preciso
// selar de novo a cada mudança de estado); lock() apaga tudo.
const openedVault = ({ userId, passphrase, identity, pub, state, trust, trustReset }) => {
  let secret = passphrase;
  const vault = {
    userId,
    identity,
    pub,
    state,
    trust,
    trustReset,
    locked: false,
    // Grava ANTES de trocar a memória: se a gravação falhar, nada fica
    // "valendo só nesta aba".
    async saveState(next) {
      if (vault.locked) throw new VaultError("LOCKED", "cofre bloqueado");
      await idbPutMany([[keyOf(userId, "state"), await e2ee.sealJson(secret, next)]]);
      vault.state = next;
    },
    async saveTrust(next) {
      if (vault.locked) throw new VaultError("LOCKED", "cofre bloqueado");
      await idbPutMany([[keyOf(userId, "trust"), await e2ee.sealJson(secret, next)]]);
      vault.trust = next;
    },
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
  const state = emptyState();
  const trust = { ...e2ee.emptyTrustStore(), id: trustStoreId };
  await idbPutMany([
    [keyOf(userId, "identity"), sealedIdentity],
    [keyOf(userId, "state"), await e2ee.sealJson(passphrase, state)],
    [keyOf(userId, "trust"), await e2ee.sealJson(passphrase, trust)],
  ]);
  const { ecdhPub, ecdsaPub } = exported;
  return openedVault({ userId, passphrase, identity: await importIdentityNonExtractable(exported), pub: { ecdhPub, ecdsaPub }, state, trust, trustReset: false });
};

// Senha errada e registro adulterado são indistinguíveis (BAD_PASSPHRASE,
// do keystore.js); nada é sobrescrito numa falha.
export const unlockVault = async ({ userId, passphrase }) => {
  const sealedIdentity = await idbGet(keyOf(userId, "identity"));
  if (!sealedIdentity) throw new VaultError("NO_VAULT", "não há cofre para esta conta neste navegador");
  const opened = await e2ee.openJson(passphrase, sealedIdentity);
  if (opened.userId !== userId) throw new VaultError("WRONG_USER", "este cofre é de outra conta");
  const sealedState = await idbGet(keyOf(userId, "state"));
  const state = sealedState ? { ...emptyState(), ...(await e2ee.openJson(passphrase, sealedState)) } : emptyState();
  const sealedTrust = await idbGet(keyOf(userId, "trust"));
  let trust;
  let trustReset = false;
  if (sealedTrust) {
    trust = await e2ee.openJson(passphrase, sealedTrust);
    if (trust.id !== opened.trustStoreId) {
      throw new VaultError("TRUST_MISMATCH", "o trust store deste navegador não pertence a este cofre; nada foi alterado");
    }
  } else {
    // P1 da 4b-2: trust store sumiu com o cofre ainda lá → TOFU reiniciado,
    // com aviso (quem chama mostra: todos voltam a "não verificado").
    trust = { ...e2ee.emptyTrustStore(), id: opened.trustStoreId };
    await idbPutMany([[keyOf(userId, "trust"), await e2ee.sealJson(passphrase, trust)]]);
    trustReset = true;
  }
  const { ecdhPub, ecdsaPub } = opened.identity;
  const identity = await importIdentityNonExtractable(opened.identity);
  return openedVault({ userId, passphrase, identity, pub: { ecdhPub, ecdsaPub }, state, trust, trustReset });
};
