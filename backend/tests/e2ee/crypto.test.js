// Núcleo da E2EE (shared/e2ee): ida e volta, e cada adulteração possível
// (texto cifrado, IV, dados associados, assinatura, chave, destinatário)
// precisa FALHAR — nunca devolver texto "quase certo".
const nodeCrypto = require("node:crypto");
const e2ee = require("../../../shared/e2ee");

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const utf8 = (s) => new TextEncoder().encode(s);

// Troca um caractere de uma string base64url por outro válido.
const flip = (s, at = 5) => s.slice(0, at) + (s[at] === "A" ? "B" : "A") + s.slice(at + 1);

describe("vetores de teste conhecidos (as primitivas são as do Web Crypto, sem nada à mão)", () => {
  test("SHA-256('abc') — FIPS 180-2", async () => {
    expect(hex(await e2ee.primitives.sha256(utf8("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
  });

  test("HKDF-SHA-256 — RFC 5869, caso de teste 1", async () => {
    const ikm = new Uint8Array(22).fill(0x0b);
    const salt = Uint8Array.from(Buffer.from("000102030405060708090a0b0c", "hex"));
    const info = Uint8Array.from(Buffer.from("f0f1f2f3f4f5f6f7f8f9", "hex"));
    expect(hex(await e2ee.primitives.hkdf(ikm, salt, info, 42))).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
  });

  test("PBKDF2-HMAC-SHA-256 ('password', 'salt', c=1 e c=2)", async () => {
    expect(hex(await e2ee.primitives.pbkdf2(utf8("password"), utf8("salt"), 1, 32))).toBe(
      "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
    expect(hex(await e2ee.primitives.pbkdf2(utf8("password"), utf8("salt"), 2, 32))).toBe(
      "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
    );
  });

  test("AES-256-GCM — McGrew/Viega casos 13 e 14 (chave e IV zerados)", async () => {
    const key = new Uint8Array(32);
    const iv = new Uint8Array(12);
    expect(hex(await e2ee.primitives.aesGcmEncryptRaw(key, iv, new Uint8Array(0)))).toBe(
      "530f8afbc74536b9a963b4f1c4cb738b"
    );
    expect(hex(await e2ee.primitives.aesGcmEncryptRaw(key, iv, new Uint8Array(16)))).toBe(
      "cea7403d4d606b6e074ec5d3baf39d18" + "d0d1c8a799996bf0265b98b5d48ab919"
    );
  });

  test("ECDSA P-256: assinatura r||s de 64 bytes, verificável pelo OpenSSL do Node", async () => {
    const id = await e2ee.generateIdentity();
    const { ecdsaPub } = await e2ee.exportPublicKeys(id);
    const data = utf8("mensagem");
    const sig = await e2ee.primitives.ecdsaSign(id.ecdsa.privateKey, data);
    expect(sig).toHaveLength(64);
    const pub = nodeCrypto.createPublicKey({ key: Buffer.from(ecdsaPub, "base64url"), format: "der", type: "spki" });
    expect(nodeCrypto.verify("sha256", data, { key: pub, dsaEncoding: "ieee-p1363" }, sig)).toBe(true);
  });

  test("ECDH P-256: mesmo segredo que o OpenSSL do Node calcula", async () => {
    const a = await e2ee.generateIdentity();
    const b = await e2ee.generateIdentity();
    const ours = await e2ee.primitives.ecdhSecret(a.ecdh.privateKey, b.ecdh.publicKey);
    const { ecdhPriv } = await e2ee.exportIdentity(a);
    const { ecdhPub } = await e2ee.exportPublicKeys(b);
    const theirs = nodeCrypto.diffieHellman({
      privateKey: nodeCrypto.createPrivateKey({ key: Buffer.from(ecdhPriv, "base64url"), format: "der", type: "pkcs8" }),
      publicKey: nodeCrypto.createPublicKey({ key: Buffer.from(ecdhPub, "base64url"), format: "der", type: "spki" }),
    });
    expect(hex(ours)).toBe(theirs.toString("hex"));
  });
});

describe("base64url estrito", () => {
  test("ida e volta", () => {
    const bytes = Uint8Array.from([0, 255, 250, 1, 2, 3, 62, 63]);
    expect(e2ee.encoding.fromB64url(e2ee.encoding.toB64url(bytes))).toEqual(bytes);
  });

  test.each(["ab+c", "ab/c", "abc=", "a", "abcd\n", "ab c"])("recusa %j", (s) => {
    expect(() => e2ee.encoding.fromB64url(s)).toThrow();
  });

  test("recusa forma não canônica (bits de sobra diferentes de zero)", () => {
    // "AB" decodifica para 1 byte, mas os 4 bits finais de "B" não são zero.
    expect(() => e2ee.encoding.fromB64url("AB")).toThrow();
    expect(e2ee.encoding.fromB64url("AA")).toEqual(Uint8Array.from([0]));
  });
});

describe("identidade, fingerprint e número de segurança", () => {
  test("chaves públicas em SPKI base64url; reimportar dá a mesma fingerprint", async () => {
    const id = await e2ee.generateIdentity();
    const pub = await e2ee.exportPublicKeys(id);
    expect(pub.ecdhPub).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(pub.ecdsaPub).toMatch(/^[A-Za-z0-9_-]+$/);
    const fp = await e2ee.fingerprint(pub);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
    const restored = await e2ee.importIdentity(await e2ee.exportIdentity(id));
    expect(await e2ee.fingerprint(await e2ee.exportPublicKeys(restored))).toBe(fp);
  });

  test("fingerprint muda se qualquer uma das duas chaves mudar", async () => {
    const a = await e2ee.exportPublicKeys(await e2ee.generateIdentity());
    const b = await e2ee.exportPublicKeys(await e2ee.generateIdentity());
    const fp = await e2ee.fingerprint(a);
    expect(await e2ee.fingerprint({ ...a, ecdhPub: b.ecdhPub })).not.toBe(fp);
    expect(await e2ee.fingerprint({ ...a, ecdsaPub: b.ecdsaPub })).not.toBe(fp);
  });

  test("número de segurança: 12 grupos de 5 dígitos, simétrico e estável", async () => {
    const alice = { userId: 3, ...(await e2ee.exportPublicKeys(await e2ee.generateIdentity())) };
    const bob = { userId: 11, ...(await e2ee.exportPublicKeys(await e2ee.generateIdentity())) };
    const ab = await e2ee.safetyNumber(alice, bob);
    expect(ab).toMatch(/^\d{5}( \d{5}){11}$/);
    expect(await e2ee.safetyNumber(bob, alice)).toBe(ab);
    expect(await e2ee.safetyNumber({ ...alice }, { ...bob })).toBe(ab);
  });

  test("número de segurança muda se uma chave ou um userId mudar", async () => {
    const alice = { userId: 3, ...(await e2ee.exportPublicKeys(await e2ee.generateIdentity())) };
    const bob = { userId: 11, ...(await e2ee.exportPublicKeys(await e2ee.generateIdentity())) };
    const mallory = await e2ee.exportPublicKeys(await e2ee.generateIdentity());
    const ab = await e2ee.safetyNumber(alice, bob);
    expect(await e2ee.safetyNumber(alice, { ...bob, ecdsaPub: mallory.ecdsaPub })).not.toBe(ab);
    expect(await e2ee.safetyNumber(alice, { ...bob, ecdhPub: mallory.ecdhPub })).not.toBe(ab);
    expect(await e2ee.safetyNumber(alice, { ...bob, userId: 12 })).not.toBe(ab);
  });

  test("importPublicKeys recusa chave que não é P-256 SPKI", async () => {
    const pub = await e2ee.exportPublicKeys(await e2ee.generateIdentity());
    const rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey;
    const rsaSpki = rsa.export({ format: "der", type: "spki" }).toString("base64url");
    await expect(e2ee.importPublicKeys({ ...pub, ecdsaPub: rsaSpki })).rejects.toThrow();
    await expect(e2ee.importPublicKeys({ ...pub, ecdhPub: "AAAA" })).rejects.toThrow();
  });
});

describe("chave da sala: wrap por membro", () => {
  let alice;
  let bob;
  let carol;
  let roomKey;
  const ctx = { roomId: 7, version: 1, senderId: 3, recipientId: 11 };

  beforeAll(async () => {
    alice = await e2ee.generateIdentity();
    bob = await e2ee.generateIdentity();
    carol = await e2ee.generateIdentity();
    alice.pub = await e2ee.exportPublicKeys(alice);
    bob.pub = await e2ee.exportPublicKeys(bob);
    carol.pub = await e2ee.exportPublicKeys(carol);
    roomKey = await e2ee.generateRoomKey();
  });

  const wrapForBob = () =>
    e2ee.wrapRoomKey({ ...ctx, roomKey, recipientEcdhPub: bob.pub.ecdhPub, senderEcdsaKey: alice.ecdsa.privateKey });
  const unwrapAsBob = (wrap, overrides = {}) =>
    e2ee.unwrapRoomKey({
      ...ctx,
      wrap,
      recipientEcdhKey: bob.ecdh.privateKey,
      senderEcdsaPub: alice.pub.ecdsaPub,
      ...overrides,
    });
  // Usa a chave desembrulhada para decifrar algo cifrado com a original.
  const sameKey = async (k) => {
    const body = await e2ee.encryptMessage({ roomKey, kv: 1, roomId: 7, senderId: 3, cid: "c1", text: "x", senderEcdsaKey: alice.ecdsa.privateKey });
    return (await e2ee.decryptMessage({ body, roomKeys: { 1: k }, roomId: 7, senderId: 3, cid: "c1", senderEcdsaPub: alice.pub.ecdsaPub })) === "x";
  };

  test("ida e volta: Bob recupera exatamente a chave da sala", async () => {
    const wrap = await wrapForBob();
    expect(Object.keys(wrap).sort()).toEqual(["ephPub", "iv", "sig", "wrapped"]);
    expect(await sameKey(await unwrapAsBob(wrap))).toBe(true);
  });

  test("cada wrap usa um par efêmero novo e um IV novo", async () => {
    const w1 = await wrapForBob();
    const w2 = await wrapForBob();
    expect(w1.ephPub).not.toBe(w2.ephPub);
    expect(w1.iv).not.toBe(w2.iv);
  });

  test("destinatário errado (Carol com o wrap do Bob) não abre", async () => {
    await expect(unwrapAsBob(await wrapForBob(), { recipientEcdhKey: carol.ecdh.privateKey })).rejects.toThrow();
  });

  test("wrap assinado por outro (Carol se passando pela Alice) é rejeitado", async () => {
    const forged = await e2ee.wrapRoomKey({ ...ctx, roomKey, recipientEcdhPub: bob.pub.ecdhPub, senderEcdsaKey: carol.ecdsa.privateKey });
    await expect(unwrapAsBob(forged)).rejects.toThrow(e2ee.E2eeError);
  });

  test.each(["ephPub", "iv", "wrapped", "sig"])("adulterar %s do wrap falha", async (field) => {
    const wrap = await wrapForBob();
    await expect(unwrapAsBob({ ...wrap, [field]: flip(wrap[field]) })).rejects.toThrow();
  });

  test.each([
    ["roomId", { roomId: 8 }],
    ["version", { version: 2 }],
    ["recipientId", { recipientId: 12 }],
    ["senderId", { senderId: 4 }],
  ])("wrap reapresentado em outro contexto (%s) falha", async (_label, overrides) => {
    await expect(unwrapAsBob(await wrapForBob(), overrides)).rejects.toThrow();
  });

  test("assinatura válida mas texto cifrado de outro wrap (troca de campos) falha", async () => {
    const w1 = await wrapForBob();
    const w2 = await wrapForBob();
    await expect(unwrapAsBob({ ...w1, wrapped: w2.wrapped })).rejects.toThrow();
  });
});

describe("mensagens: envelope cifrado e assinado", () => {
  let alice;
  let roomKey;
  let otherKey;
  const ctx = { roomId: 7, senderId: 3, cid: "3f2b-cid" };

  beforeAll(async () => {
    alice = await e2ee.generateIdentity();
    alice.pub = await e2ee.exportPublicKeys(alice);
    roomKey = await e2ee.generateRoomKey();
    otherKey = await e2ee.generateRoomKey();
  });

  const encrypt = (text, overrides = {}) =>
    e2ee.encryptMessage({ ...ctx, roomKey, kv: 1, text, senderEcdsaKey: alice.ecdsa.privateKey, ...overrides });
  const decrypt = (body, overrides = {}) =>
    e2ee.decryptMessage({ ...ctx, body, roomKeys: { 1: roomKey }, senderEcdsaPub: alice.pub.ecdsaPub, ...overrides });

  test("ida e volta (UTF-8 multibyte)", async () => {
    const text = "olá, ✓ 🔐 mundo";
    expect(await decrypt(await encrypt(text))).toBe(text);
  });

  test("o envelope é JSON canônico {v,kv,iv,ct,sig} e não contém o texto", async () => {
    const body = await encrypt("MARCADOR-SECRETO");
    expect(body).not.toContain("MARCADOR");
    const env = JSON.parse(body);
    expect(Object.keys(env)).toEqual(["v", "kv", "iv", "ct", "sig"]);
    expect(JSON.stringify(env)).toBe(body);
    expect(env).toMatchObject({ v: 1, kv: 1 });
    expect(e2ee.encoding.fromB64url(env.iv)).toHaveLength(12);
    expect(e2ee.encoding.fromB64url(env.sig)).toHaveLength(64);
  });

  test("IV aleatório: o mesmo texto cifra diferente a cada vez", async () => {
    const a = JSON.parse(await encrypt("igual"));
    const b = JSON.parse(await encrypt("igual"));
    expect(a.iv).not.toBe(b.iv);
    expect(a.ct).not.toBe(b.ct);
  });

  test.each([
    ["1 byte", 1, 128],
    ["126 bytes (cabe com o prefixo de 2)", 126, 128],
    ["127 bytes", 127, 256],
    ["300 bytes", 300, 384],
  ])("padding em blocos de 128: %s → %i bytes cifrados (+16 da tag)", async (_l, size, padded) => {
    const { ct } = JSON.parse(await encrypt("a".repeat(size)));
    expect(e2ee.encoding.fromB64url(ct)).toHaveLength(padded + 16);
  });

  test("textos de tamanhos parecidos ficam com o mesmo tamanho cifrado", async () => {
    const short = JSON.parse(await encrypt("sim")).ct.length;
    const longer = JSON.parse(await encrypt("não, de jeito nenhum, amanhã")).ct.length;
    expect(longer).toBe(short);
  });

  test("o maior texto aceito gera body dentro do limite do protocolo; acima disso, recusa", async () => {
    const body = await encrypt("a".repeat(e2ee.MAX_TEXT_BYTES));
    expect(new TextEncoder().encode(body).length).toBeLessThanOrEqual(8192);
    await expect(encrypt("a".repeat(e2ee.MAX_TEXT_BYTES + 1))).rejects.toThrow(e2ee.E2eeError);
    await expect(encrypt("")).rejects.toThrow(e2ee.E2eeError);
  });

  test.each(["ct", "iv", "sig"])("adulterar %s falha", async (field) => {
    const env = JSON.parse(await encrypt("oi"));
    await expect(decrypt(JSON.stringify({ ...env, [field]: flip(env[field]) }))).rejects.toThrow(e2ee.E2eeError);
  });

  test.each([
    ["sala", { roomId: 8 }],
    ["remetente (o servidor trocou o from)", { senderId: 4 }],
    ["cid", { cid: "outro-cid" }],
  ])("AAD diferente — %s — falha", async (_label, overrides) => {
    await expect(decrypt(await encrypt("oi"), overrides)).rejects.toThrow(e2ee.E2eeError);
  });

  test("kv do envelope alterado falha (AAD e assinatura cobrem a versão)", async () => {
    const env = JSON.parse(await encrypt("oi"));
    await expect(decrypt(JSON.stringify({ ...env, kv: 2 }), { roomKeys: { 1: roomKey, 2: roomKey } })).rejects.toThrow();
  });

  test("chave de sala errada falha", async () => {
    await expect(decrypt(await encrypt("oi"), { roomKeys: { 1: otherKey } })).rejects.toThrow(e2ee.E2eeError);
  });

  test("sem a chave da versão do envelope: erro claro (MISSING_KEY)", async () => {
    await expect(decrypt(await encrypt("oi"), { roomKeys: {} })).rejects.toMatchObject({ code: "MISSING_KEY" });
  });

  test("assinatura de outro usuário (chave fixada não confere) falha mesmo com a chave da sala certa", async () => {
    const mallory = await e2ee.generateIdentity();
    const forged = await encrypt("sou a alice", { senderEcdsaKey: mallory.ecdsa.privateKey });
    await expect(decrypt(forged)).rejects.toThrow(e2ee.E2eeError);
  });

  test.each([
    ["texto puro", "oi, tudo bem?"],
    ["JSON sem cifra", '{"text":"oi"}'],
    ["campo extra", (env) => JSON.stringify({ ...env, text: "oi" })],
    ["v diferente", (env) => JSON.stringify({ ...env, v: 2 })],
    ["fora da forma canônica (espaços)", (env) => JSON.stringify(env, null, 1)],
  ])("parseEnvelope recusa %s", async (_label, make) => {
    const env = JSON.parse(await encrypt("oi"));
    const body = typeof make === "function" ? make(env) : make;
    expect(() => e2ee.parseEnvelope(body)).toThrow(e2ee.E2eeError);
  });
});
