// Etapa 5 (A1): envelope v2 com expiração assinada (exp) e (A3) nome da sala
// cifrado. Os testes de ataque vêm primeiro: o servidor não consegue mudar
// o exp sem quebrar a assinatura, e o cliente recusa exp vencido ou absurdo.
const e2ee = require("../../../shared/e2ee");

const NOW_MS = Date.UTC(2026, 9, 30, 12, 0, 0);
const NOW = NOW_MS / 1000;

let alice;
let roomKey;
const ctx = { roomId: 7, senderId: 3, cid: "cid-efemera" };

beforeAll(async () => {
  alice = await e2ee.generateIdentity();
  alice.pub = await e2ee.exportPublicKeys(alice);
  roomKey = await e2ee.generateRoomKey();
});

const encrypt = (overrides = {}) =>
  e2ee.encryptMessage({ ...ctx, roomKey, kv: 1, text: "some daqui a pouco", senderEcdsaKey: alice.ecdsa.privateKey, ...overrides });
const decrypt = (body, overrides = {}) =>
  e2ee.decryptMessage({ ...ctx, body, roomKeys: { 1: roomKey }, senderEcdsaPub: alice.pub.ecdsaPub, nowMs: NOW_MS, ...overrides });

describe("envelope v2 {v,kv,iv,ct,sig,exp}", () => {
  test("sem expiração: exp null, v = 2, nessa ordem de chaves", async () => {
    const env = JSON.parse(await encrypt());
    expect(Object.keys(env)).toEqual(["v", "kv", "iv", "ct", "sig", "exp"]);
    expect(env).toMatchObject({ v: 2, kv: 1, exp: null });
    expect(await decrypt(JSON.stringify(env))).toBe("some daqui a pouco");
  });

  test("com expiração: exp em segundos Unix, decifra antes de vencer", async () => {
    const body = await encrypt({ exp: NOW + 3600 });
    expect(JSON.parse(body).exp).toBe(NOW + 3600);
    expect(await decrypt(body)).toBe("some daqui a pouco");
  });

  test("ATAQUE: o servidor estende o exp → assinatura não confere", async () => {
    const env = JSON.parse(await encrypt({ exp: NOW + 60 }));
    await expect(decrypt(JSON.stringify({ ...env, exp: NOW + 7 * 86400 }))).rejects.toMatchObject({ code: "INVALID_MESSAGE" });
  });

  test("ATAQUE: o servidor tira o exp (vira null) → assinatura não confere", async () => {
    const env = JSON.parse(await encrypt({ exp: NOW + 60 }));
    await expect(decrypt(JSON.stringify({ ...env, exp: null }))).rejects.toMatchObject({ code: "INVALID_MESSAGE" });
  });

  test("ATAQUE: o servidor põe exp numa mensagem sem expiração → assinatura não confere", async () => {
    const env = JSON.parse(await encrypt());
    await expect(decrypt(JSON.stringify({ ...env, exp: NOW + 60 }))).rejects.toMatchObject({ code: "INVALID_MESSAGE" });
  });

  test("vencida: EXPIRED (não decifra nem mostra)", async () => {
    const body = await encrypt({ exp: NOW + 60 });
    await expect(decrypt(body, { nowMs: (NOW + 60) * 1000 })).rejects.toMatchObject({ code: "EXPIRED" });
  });

  test("ATAQUE: exp acima de 7 dias + tolerância (remetente burlando o limite) → inválida", async () => {
    const body = await encrypt({ exp: NOW + e2ee.MAX_TTL_SECONDS + e2ee.CLOCK_SKEW_SECONDS + 1 });
    await expect(decrypt(body)).rejects.toMatchObject({ code: "INVALID_MESSAGE" });
  });

  test.each([
    ["texto", "123"],
    ["fracionário", 1.5],
    ["zero", 0],
    ["negativo", -5],
    ["booleano", true],
  ])("exp %s → INVALID_ENVELOPE", async (_label, exp) => {
    const env = JSON.parse(await encrypt());
    expect(() => e2ee.parseEnvelope(JSON.stringify({ ...env, exp }))).toThrow(expect.objectContaining({ code: "INVALID_ENVELOPE" }));
  });

  test("envelope v1 (sem exp) não é mais aceito", async () => {
    const { exp, ...v1 } = JSON.parse(await encrypt());
    expect(exp).toBeNull();
    expect(() => e2ee.parseEnvelope(JSON.stringify({ ...v1, v: 1 }))).toThrow(e2ee.E2eeError);
  });

  test("encryptMessage recusa exp malformado", async () => {
    await expect(encrypt({ exp: "amanhã" })).rejects.toMatchObject({ code: "INVALID_TTL" });
    await expect(encrypt({ exp: 1.5 })).rejects.toMatchObject({ code: "INVALID_TTL" });
  });
});

describe("expiração no cliente", () => {
  test("presets: 1min, 1h, 24h e 7d", () => {
    expect(e2ee.TTL_PRESETS).toEqual({ "1min": 60, "1h": 3600, "24h": 86400, "7d": 604800 });
  });

  test("expFor arredonda para CIMA no minuto (não revela o segundo do envio) e nunca encurta o TTL", () => {
    const sent = NOW_MS + 17_250; // 12:00:17.25
    const exp = e2ee.expFor(60, sent);
    expect(exp % 60).toBe(0);
    expect(exp).toBeGreaterThanOrEqual(Math.ceil(sent / 1000) + 60);
    expect(exp).toBeLessThan(Math.ceil(sent / 1000) + 120);
    expect(e2ee.expFor(null, sent)).toBeNull();
  });

  test("expFor recusa TTL fora de 30 s..7 d", () => {
    expect(() => e2ee.expFor(10, NOW_MS)).toThrow(expect.objectContaining({ code: "INVALID_TTL" }));
    expect(() => e2ee.expFor(e2ee.MAX_TTL_SECONDS + 1, NOW_MS)).toThrow(expect.objectContaining({ code: "INVALID_TTL" }));
  });

  test("receiver: vencida → expired (não marca o cid como visto); válida devolve o exp", async () => {
    const senderKeyFor = async () => ({ ecdsaPub: alice.pub.ecdsaPub, trust: "unverified" });
    const roomKeysFor = async () => ({ 1: roomKey });
    let now = NOW_MS;
    const receiver = e2ee.createReceiver({ roomKeysFor, senderKeyFor, nowMs: () => now });
    const body = await encrypt({ exp: NOW + 120 });
    const packet = { room: ctx.roomId, from: ctx.senderId, cid: ctx.cid, body };
    now = (NOW + 120) * 1000;
    expect(await receiver.accept(packet)).toEqual({ status: "expired" });
    now = NOW_MS;
    expect(await receiver.accept(packet)).toMatchObject({ status: "ok", text: "some daqui a pouco", exp: NOW + 120 });
  });
});

describe("nome da sala cifrado (A3)", () => {
  const nameCtx = { roomId: 7, kv: 1 };

  test("ida e volta; o envelope não contém o nome e cabe em 512 bytes", async () => {
    const nameEnv = await e2ee.encryptRoomName({ ...nameCtx, roomKey, name: "Grupo de Redes 🔐" });
    expect(nameEnv).not.toContain("Grupo");
    expect(new TextEncoder().encode(nameEnv).length).toBeLessThanOrEqual(512);
    expect(e2ee.parseRoomNameEnvelope(nameEnv)).toEqual({ kv: 1 });
    expect(await e2ee.decryptRoomName({ roomId: 7, nameEnv, roomKeys: { 1: roomKey } })).toBe("Grupo de Redes 🔐");
  });

  test("o maior nome aceito cabe em 512 bytes; acima, recusa", async () => {
    const nameEnv = await e2ee.encryptRoomName({ ...nameCtx, roomKey, name: "a".repeat(e2ee.MAX_ROOM_NAME_BYTES) });
    expect(new TextEncoder().encode(nameEnv).length).toBeLessThanOrEqual(512);
    await expect(e2ee.encryptRoomName({ ...nameCtx, roomKey, name: "a".repeat(e2ee.MAX_ROOM_NAME_BYTES + 1) })).rejects.toThrow(e2ee.E2eeError);
    await expect(e2ee.encryptRoomName({ ...nameCtx, roomKey, name: "" })).rejects.toThrow(e2ee.E2eeError);
  });

  test("ATAQUE: nome de outra sala ou de outra versão (servidor troca) não decifra", async () => {
    const nameEnv = await e2ee.encryptRoomName({ ...nameCtx, roomKey, name: "Sala A" });
    await expect(e2ee.decryptRoomName({ roomId: 8, nameEnv, roomKeys: { 1: roomKey } })).rejects.toMatchObject({ code: "INVALID_NAME" });
    const env = JSON.parse(nameEnv);
    await expect(e2ee.decryptRoomName({ roomId: 7, nameEnv: JSON.stringify({ ...env, kv: 2 }), roomKeys: { 2: roomKey } })).rejects.toMatchObject({ code: "INVALID_NAME" });
  });

  test("sem a chave da versão: MISSING_KEY", async () => {
    const nameEnv = await e2ee.encryptRoomName({ ...nameCtx, roomKey, name: "Sala A" });
    await expect(e2ee.decryptRoomName({ roomId: 7, nameEnv, roomKeys: {} })).rejects.toMatchObject({ code: "MISSING_KEY" });
  });

  test.each([
    ["texto puro", "Sala A"],
    ["campo extra", (env) => JSON.stringify({ ...env, name: "x" })],
    ["ordem trocada", (env) => JSON.stringify({ kv: env.kv, v: env.v, iv: env.iv, ct: env.ct })],
    ["ct sem padding", (env) => JSON.stringify({ ...env, ct: e2ee.encoding.toB64url(new Uint8Array(140)) })],
  ])("parseRoomNameEnvelope recusa %s", async (_label, make) => {
    const env = JSON.parse(await e2ee.encryptRoomName({ ...nameCtx, roomKey, name: "Sala A" }));
    const body = typeof make === "function" ? make(env) : make;
    expect(() => e2ee.parseRoomNameEnvelope(body)).toThrow(e2ee.E2eeError);
  });
});
