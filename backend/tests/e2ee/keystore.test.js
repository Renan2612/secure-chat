// Keystore e trust store do cliente (D2, D6): as chaves privadas e os pins
// de chaves alheias só existem cifrados em repouso, num arquivo 0600 fora de
// qualquer repositório, e a senha de cifragem errada não abre nada.
const fs = require("fs");
const os = require("os");
const path = require("path");
const e2ee = require("../../../shared/e2ee");
const store = require("../../../shared/e2ee/node");

const PASS = "senha-de-cifragem-longa";
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "sc-keystore-"));
const flip = (s, at = 5) => s.slice(0, at) + (s[at] === "A" ? "B" : "A") + s.slice(at + 1);

describe("keystore (núcleo isomórfico)", () => {
  let identity;
  let sealed;

  beforeAll(async () => {
    identity = await e2ee.exportIdentity(await e2ee.generateIdentity());
    sealed = await e2ee.sealJson(PASS, { identity });
  });

  test("ida e volta com a senha certa", async () => {
    expect((await e2ee.openJson(PASS, sealed)).identity).toEqual(identity);
  });

  test("o arquivo selado não contém nenhuma chave privada nem pública em claro", () => {
    const text = JSON.stringify(sealed);
    for (const value of Object.values(identity)) expect(text).not.toContain(value);
  });

  test("PBKDF2-SHA-256 com pelo menos 600.000 iterações e salt aleatório", async () => {
    expect(sealed.kdf).toMatchObject({ name: "PBKDF2-SHA-256" });
    expect(sealed.kdf.iterations).toBeGreaterThanOrEqual(600000);
    const other = await e2ee.sealJson(PASS, { identity });
    expect(other.kdf.salt).not.toBe(sealed.kdf.salt);
    expect(other.iv).not.toBe(sealed.iv);
  });

  test("senha errada falha com BAD_PASSPHRASE", async () => {
    await expect(e2ee.openJson("outra-senha-qualquer", sealed)).rejects.toMatchObject({ code: "BAD_PASSPHRASE" });
  });

  test.each([
    ["ct", (s) => ({ ...s, ct: flip(s.ct) })],
    ["iv", (s) => ({ ...s, iv: flip(s.iv) })],
    ["salt", (s) => ({ ...s, kdf: { ...s.kdf, salt: flip(s.kdf.salt) } })],
    ["iterações (rebaixar o custo)", (s) => ({ ...s, kdf: { ...s.kdf, iterations: 600001 } })],
  ])("arquivo adulterado (%s) não abre", async (_label, tamper) => {
    await expect(e2ee.openJson(PASS, tamper(sealed))).rejects.toThrow(e2ee.E2eeError);
  });

  test("abaixo de 600.000 iterações: recusa ao gravar e ao abrir", async () => {
    await expect(e2ee.sealJson(PASS, {}, { iterations: 1000 })).rejects.toThrow(/600000/);
    await expect(e2ee.openJson(PASS, { ...sealed, kdf: { ...sealed.kdf, iterations: 1000 } })).rejects.toThrow(e2ee.E2eeError);
  });

  test("senha de cifragem curta ou vazia é recusada", async () => {
    await expect(e2ee.sealJson("curta", {})).rejects.toMatchObject({ code: "WEAK_PASSPHRASE" });
    await expect(e2ee.sealJson("", {})).rejects.toMatchObject({ code: "WEAK_PASSPHRASE" });
  });
});

describe("arquivos no disco (adaptador Node)", () => {
  test("grava com permissão 0600 em diretório 0700", async () => {
    const dir = path.join(tmp(), "secure-chat");
    const file = path.join(dir, "alice@example.com.json");
    await store.writeSealedFile(file, PASS, { a: 1 });
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
    expect(await store.readSealedFile(file, PASS)).toEqual({ a: 1 });
  });

  test("recusa abrir arquivo com permissão aberta para grupo/outros", async () => {
    const file = path.join(tmp(), "k.json");
    await store.writeSealedFile(file, PASS, { a: 1 });
    fs.chmodSync(file, 0o644);
    await expect(store.readSealedFile(file, PASS)).rejects.toThrow(/permiss/i);
  });

  test("recusa link simbólico no lugar do arquivo", async () => {
    const dir = tmp();
    const real = path.join(dir, "real.json");
    await store.writeSealedFile(real, PASS, { a: 1 });
    fs.symlinkSync(real, path.join(dir, "link.json"));
    await expect(store.readSealedFile(path.join(dir, "link.json"), PASS)).rejects.toThrow(/link/i);
  });

  test("nunca dentro do repositório do projeto", async () => {
    const inside = path.join(__dirname, "keystore-proibido.json");
    await expect(store.writeSealedFile(inside, PASS, {})).rejects.toThrow(/reposit/i);
    expect(fs.existsSync(inside)).toBe(false);
  });

  test("nunca dentro de QUALQUER repositório git", async () => {
    const repo = tmp();
    fs.mkdirSync(path.join(repo, ".git"));
    const file = path.join(repo, "sub", "k.json");
    await expect(store.writeSealedFile(file, PASS, {})).rejects.toThrow(/reposit/i);
    expect(fs.existsSync(file)).toBe(false);
  });

  test("caminho padrão: ~/.config/secure-chat/<email>.json; trust store ao lado", () => {
    const home = tmp();
    const file = store.defaultKeystorePath("alice@example.com", home);
    expect(file).toBe(path.join(home, ".config", "secure-chat", "alice@example.com.json"));
    expect(store.trustStorePath(file)).toBe(path.join(home, ".config", "secure-chat", "alice@example.com.trust.json"));
  });

  test.each(["../x@example.com", "a/b@example.com", "", "x\0@example.com"])("e-mail %j não vira caminho", (email) => {
    expect(() => store.defaultKeystorePath(email, tmp())).toThrow();
  });

  test("senha errada no arquivo do disco também falha", async () => {
    const file = path.join(tmp(), "k.json");
    await store.writeSealedFile(file, PASS, { a: 1 });
    await expect(store.readSealedFile(file, "senha-errada-123")).rejects.toMatchObject({ code: "BAD_PASSPHRASE" });
  });
});

describe("trust store (TOFU)", () => {
  let k1;
  let k2;

  beforeAll(async () => {
    k1 = await e2ee.exportPublicKeys(await e2ee.generateIdentity());
    k2 = await e2ee.exportPublicKeys(await e2ee.generateIdentity());
  });

  test("primeira chave vista é fixada (não verificada); a mesma de novo confere", async () => {
    let trust = e2ee.emptyTrustStore();
    let r = await e2ee.observeKeys(trust, 11, k1);
    expect(r.status).toBe("PINNED");
    trust = r.store;
    expect(e2ee.trustState(trust, 11, k1)).toBe("unverified");
    r = await e2ee.observeKeys(trust, 11, k1);
    expect(r.status).toBe("MATCH");
  });

  test("chave alterada: CHANGED, deixa de ser confiável até o usuário confirmar", async () => {
    let trust = (await e2ee.observeKeys(e2ee.emptyTrustStore(), 11, k1)).store;
    const r = await e2ee.observeKeys(trust, 11, k2);
    expect(r.status).toBe("CHANGED");
    trust = r.store;
    expect(e2ee.trustState(trust, 11, k2)).toBe("changed");
    // A antiga também não vale mais como confiável enquanto houver mudança pendente.
    expect(e2ee.trustState(trust, 11, k1)).toBe("changed");
    // Observar de novo não "aceita" a mudança sozinho.
    expect((await e2ee.observeKeys(trust, 11, k2)).status).toBe("CHANGED");
    trust = e2ee.confirmTrust(trust, 11, await e2ee.fingerprint(k2));
    expect(e2ee.trustState(trust, 11, k2)).toBe("verified");
    expect(e2ee.trustState(trust, 11, k1)).toBe("changed");
  });

  test("confirmar sem mudança pendente marca como verificado", async () => {
    const trust = e2ee.confirmTrust((await e2ee.observeKeys(e2ee.emptyTrustStore(), 11, k1)).store, 11, await e2ee.fingerprint(k1));
    expect(e2ee.trustState(trust, 11, k1)).toBe("verified");
  });

  test("ataque: a chave muda DE NOVO entre o usuário comparar e confirmar — a confirmação é recusada", async () => {
    const k3 = await e2ee.exportPublicKeys(await e2ee.generateIdentity());
    let trust = (await e2ee.observeKeys(e2ee.emptyTrustStore(), 11, k1)).store;
    trust = (await e2ee.observeKeys(trust, 11, k2)).store;
    const compared = await e2ee.fingerprint(k2); // o usuário conferiu o número de segurança com k2
    trust = (await e2ee.observeKeys(trust, 11, k3)).store; // o servidor troca para k3 nesse meio-tempo
    expect(() => e2ee.confirmTrust(trust, 11, compared)).toThrow(/fingerprint/i);
    expect(e2ee.trustState(trust, 11, k3)).toBe("changed");
  });

  test("confirmar exige a fingerprint conferida (sem ela, ou errada, recusa)", async () => {
    const trust = (await e2ee.observeKeys(e2ee.emptyTrustStore(), 11, k1)).store;
    expect(() => e2ee.confirmTrust(trust, 11)).toThrow(/fingerprint/i);
    const wrongFp = await e2ee.fingerprint(k2);
    expect(() => e2ee.confirmTrust(trust, 11, wrongFp)).toThrow(/fingerprint/i);
  });

  test("usuário desconhecido: unknown; confirmar quem nunca foi visto falha", () => {
    expect(e2ee.trustState(e2ee.emptyTrustStore(), 99, k1)).toBe("unknown");
    expect(() => e2ee.confirmTrust(e2ee.emptyTrustStore(), 99, "0".repeat(64))).toThrow();
  });

  test("trust store vai para o disco cifrado; adulterado não abre", async () => {
    const file = path.join(tmp(), "t.trust.json");
    const trust = (await e2ee.observeKeys(e2ee.emptyTrustStore(), 11, k1)).store;
    await store.writeSealedFile(file, PASS, trust);
    expect(fs.readFileSync(file, "utf8")).not.toContain(k1.ecdsaPub);
    expect(await store.readSealedFile(file, PASS)).toEqual(trust);
    const sealed = JSON.parse(fs.readFileSync(file, "utf8"));
    fs.writeFileSync(file, JSON.stringify({ ...sealed, ct: flip(sealed.ct) }), { mode: 0o600 });
    await expect(store.readSealedFile(file, PASS)).rejects.toThrow(e2ee.E2eeError);
  });
});
