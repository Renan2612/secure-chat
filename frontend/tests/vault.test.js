// Cofre selado no IndexedDB (B-D2): identidade (ECDH + ECDSA), estado das
// salas (chaves recebidas, criador e versão fixados, último nome verificado
// e o maior seq) e trust store, cada um como um registro no MESMO formato do
// keystore.js (PBKDF2 >= 600 000 + AES-GCM), sob uma senha de cifragem
// DISTINTA da senha de login. Chaves privadas em memória não extraíveis;
// bloquear apaga tudo da memória. Sem recuperação.
import "fake-indexeddb/auto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, describe, expect, test } from "vitest";
import e2ee from "../src/crypto/e2ee.js";
import { createVault, unlockVault, hasVault, deleteVault, VaultError } from "../src/crypto/vault.js";
import { rawRecords } from "./helpers.js";

const PASS = "senha-de-cifragem-123";
const LOGIN = "senha-de-login-456";

beforeEach(async () => {
  await deleteVault(1);
  await deleteVault(2);
});

describe("criar", () => {
  test("cria identidade nova; os registros gravados são keystores selados (>= 600 000 iterações)", async () => {
    const vault = await createVault({ userId: 1, passphrase: PASS, loginPassword: LOGIN });
    expect(await hasVault(1)).toBe(true);
    const records = await rawRecords(1);
    expect(Object.keys(records).sort()).toEqual(["identity", "state", "trust"]);
    for (const sealed of Object.values(records)) {
      expect(sealed).toMatchObject({ format: "secure-chat-keystore", v: 1, kdf: { name: "PBKDF2-SHA-256" } });
      expect(sealed.kdf.iterations).toBeGreaterThanOrEqual(600000);
    }
    const dump = JSON.stringify(records);
    expect(dump).not.toMatch(/ecdhPriv|ecdsaPriv|roomKeys/);
    expect(dump).not.toContain(vault.pub.ecdsaPub); // nem as públicas ficam em claro
    vault.lock();
  });

  test("ATAQUE: senha de cifragem igual à de login → recusa e nada é gravado", async () => {
    await expect(createVault({ userId: 1, passphrase: LOGIN, loginPassword: LOGIN })).rejects.toMatchObject({ code: "SAME_AS_LOGIN" });
    expect(await hasVault(1)).toBe(false);
  });

  test("senha de cifragem curta → recusa (regra do keystore.js)", async () => {
    await expect(createVault({ userId: 1, passphrase: "curta", loginPassword: LOGIN })).rejects.toMatchObject({ code: "WEAK_PASSPHRASE" });
    expect(await hasVault(1)).toBe(false);
  });

  test("não sobrescreve um cofre existente", async () => {
    (await createVault({ userId: 1, passphrase: PASS, loginPassword: LOGIN })).lock();
    await expect(createVault({ userId: 1, passphrase: PASS, loginPassword: LOGIN })).rejects.toMatchObject({ code: "EXISTS" });
  });
});

describe("desbloquear", () => {
  test("a identidade volta; as privadas em memória NÃO são extraíveis e funcionam", async () => {
    const created = await createVault({ userId: 1, passphrase: PASS, loginPassword: LOGIN });
    const pub = created.pub;
    created.lock();
    const vault = await unlockVault({ userId: 1, passphrase: PASS });
    expect(vault.pub).toEqual(pub);
    for (const key of [vault.identity.ecdh.privateKey, vault.identity.ecdsa.privateKey]) {
      expect(key.extractable).toBe(false);
      await expect(crypto.subtle.exportKey("pkcs8", key)).rejects.toThrow();
    }
    const sig = await e2ee.primitives.ecdsaSign(vault.identity.ecdsa.privateKey, new Uint8Array([1, 2, 3]));
    const verifyKey = await e2ee.importVerifyKey(pub.ecdsaPub);
    expect(await e2ee.primitives.ecdsaVerify(verifyKey, sig, new Uint8Array([1, 2, 3]))).toBe(true);
    vault.lock();
  });

  test("ATAQUE: senha errada → BAD_PASSPHRASE e o cofre fica intacto", async () => {
    (await createVault({ userId: 1, passphrase: PASS, loginPassword: LOGIN })).lock();
    const before = JSON.stringify(await rawRecords(1));
    await expect(unlockVault({ userId: 1, passphrase: "outra-senha-qualquer" })).rejects.toMatchObject({ code: "BAD_PASSPHRASE" });
    expect(JSON.stringify(await rawRecords(1))).toBe(before);
  });

  test("ATAQUE: registro adulterado (rebaixar o PBKDF2 ou trocar o ct) → recusa", async () => {
    (await createVault({ userId: 1, passphrase: PASS, loginPassword: LOGIN })).lock();
    const records = await rawRecords(1);
    await rawRecords(1, { ...records, identity: { ...records.identity, kdf: { ...records.identity.kdf, iterations: 1000 } } });
    await expect(unlockVault({ userId: 1, passphrase: PASS })).rejects.toMatchObject({ code: "WEAK_KDF" });
    await rawRecords(1, { ...records, state: { ...records.state, ct: records.state.ct.replace(/^./, (c) => (c === "A" ? "B" : "A")) } });
    await expect(unlockVault({ userId: 1, passphrase: PASS })).rejects.toMatchObject({ code: "BAD_PASSPHRASE" });
  });

  test("ATAQUE: cofre de outro usuário copiado para este id → recusa", async () => {
    (await createVault({ userId: 2, passphrase: PASS, loginPassword: LOGIN })).lock();
    await rawRecords(1, await rawRecords(2));
    await expect(unlockVault({ userId: 1, passphrase: PASS })).rejects.toMatchObject({ code: "WRONG_USER" });
  });

  test("ATAQUE: trust store de OUTRO cofre (identificador diferente) → recusa, sem sobrescrever", async () => {
    (await createVault({ userId: 1, passphrase: PASS, loginPassword: LOGIN })).lock();
    (await createVault({ userId: 2, passphrase: PASS, loginPassword: LOGIN })).lock();
    const mine = await rawRecords(1);
    await rawRecords(1, { ...mine, trust: (await rawRecords(2)).trust });
    await expect(unlockVault({ userId: 1, passphrase: PASS })).rejects.toMatchObject({ code: "TRUST_MISMATCH" });
  });

  test("ATAQUE (achado da revisão do 24773f2): estado de OUTRO cofre (mesma senha) no lugar deste → recusa", async () => {
    (await createVault({ userId: 1, passphrase: PASS, loginPassword: LOGIN })).lock();
    const other = await createVault({ userId: 2, passphrase: PASS, loginPassword: LOGIN });
    await other.saveState({ ...other.state, roomKeys: { 9: { 1: "AQID" } } });
    other.lock();
    await rawRecords(1, { ...(await rawRecords(1)), state: (await rawRecords(2)).state });
    await expect(unlockVault({ userId: 1, passphrase: PASS })).rejects.toMatchObject({ code: "STATE_MISMATCH" });
  });

  test("trust store apagado: TOFU reiniciado COM aviso (trustReset), como no ws-client", async () => {
    (await createVault({ userId: 1, passphrase: PASS, loginPassword: LOGIN })).lock();
    const { trust, ...rest } = await rawRecords(1);
    expect(trust).toBeDefined();
    await rawRecords(1, rest);
    const vault = await unlockVault({ userId: 1, passphrase: PASS });
    expect(vault.trustReset).toBe(true);
    expect(vault.trust.peers).toEqual({});
    vault.lock();
    expect((await unlockVault({ userId: 1, passphrase: PASS })).trustReset).toBe(false);
  });
});

describe("estado e trust store", () => {
  test("gravar o estado (chave de sala, nome verificado com seq) e o trust store; reabrir devolve tudo", async () => {
    const vault = await createVault({ userId: 1, passphrase: PASS, loginPassword: LOGIN });
    await vault.saveState({ ...vault.state, roomKeys: { 5: { 1: "AQID" } }, roomNames: { 5: { name: "Sala", seq: 3, ownerId: 1, sig: "x" } } });
    const pinned = await e2ee.observeKeys(vault.trust, 2, (await e2ee.exportPublicKeys(await e2ee.generateIdentity())));
    await vault.saveTrust(pinned.store);
    vault.lock();
    const again = await unlockVault({ userId: 1, passphrase: PASS });
    expect(again.state.roomKeys).toEqual({ 5: { 1: "AQID" } });
    expect(again.state.roomNames[5].seq).toBe(3);
    expect(Object.keys(again.trust.peers)).toEqual(["2"]);
    again.lock();
  });

  test("bloquear apaga a memória: depois do lock, nada funciona", async () => {
    const vault = await createVault({ userId: 1, passphrase: PASS, loginPassword: LOGIN });
    vault.lock();
    expect(vault.locked).toBe(true);
    expect(vault.identity).toBeNull();
    expect(vault.state).toBeNull();
    await expect(vault.saveState({})).rejects.toBeInstanceOf(VaultError);
  });
});

test("nada de localStorage, sessionStorage nem document.cookie no código do frontend", () => {
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else if (/\.(js|jsx)$/.test(name)) files.push(path);
    }
  };
  walk(new URL("../src", import.meta.url).pathname);
  expect(files.length).toBeGreaterThan(0);
  for (const file of files) {
    expect({ file, found: /localStorage|sessionStorage|document\.cookie/.test(readFileSync(file, "utf8")) }).toEqual({ file, found: false });
  }
});
