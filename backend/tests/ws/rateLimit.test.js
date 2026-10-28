// Ataque: inundação de pacotes numa conexão autenticada (cada MSG_SEND e
// SUBSCRIBE custa uma consulta ao banco). Limite por conexão (token bucket).
const { pool, resetDb, createRoomInDb } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, closed, send } = require("./helpers");
const { DEFAULT_LIMITS } = require("../../realtime/protocol");

let srv;
let alice;

beforeEach(async () => {
  await resetDb();
  srv = null;
});
afterEach(() => srv?.stop());
afterAll(() => pool.end());

const start = async (limits) => {
  srv = await startServer(limits);
  alice = await loginUser(srv, "alice");
};

const rateErrors = (inbox) => inbox.packets.filter((p) => p.type === "ERROR" && p.code === "RATE_LIMITED");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test("padrões: rajada de 20, 10 pacotes/s, fecha na 20ª violação seguida", () => {
  expect(DEFAULT_LIMITS).toMatchObject({ rateBurst: 20, rateRefillPerSec: 10, maxRateViolations: 20 });
});

test("dentro da rajada: tudo é atendido", async () => {
  await start({ rateBurst: 10, rateRefillPerSec: 1 });
  const { ws, inbox } = await connect(srv, alice.cookie); // HELLO gasta 1
  for (let i = 0; i < 9; i += 1) send(ws, { type: "PING" });
  for (let i = 0; i < 9; i += 1) await nextPacket(inbox, "PONG");
  expect(rateErrors(inbox)).toEqual([]);
  ws.close();
});

test("excesso: pacote descartado com ERROR RATE_LIMITED (um por sequência, sem amplificar)", async () => {
  await start({ rateBurst: 5, rateRefillPerSec: 1, maxRateViolations: 100 });
  const room = await createRoomInDb("Sala", [alice.id]);
  const { ws, inbox } = await connect(srv, alice.cookie);
  for (let i = 0; i < 10; i += 1) send(ws, { type: "MSG_SEND", room, cid: `c${i}`, body: "flood" });
  await nextPacket(inbox, "ERROR");
  await sleep(300);
  expect(rateErrors(inbox)).toHaveLength(1);
  const { rows } = await pool.query("SELECT COUNT(*)::int AS n FROM messages");
  expect(rows[0].n).toBe(4); // 5 fichas − 1 do HELLO
  expect(inbox.closed).toBeNull();
  ws.close();
});

test("inundação persistente → close 4429", async () => {
  await start({ rateBurst: 5, rateRefillPerSec: 1, maxRateViolations: 10 });
  const { ws, inbox } = await connect(srv, alice.cookie);
  for (let i = 0; i < 50; i += 1) send(ws, { type: "PING" });
  expect((await closed(inbox)).code).toBe(4429);
});

test("quem se acalma (balde cheio de novo) zera as violações", async () => {
  await start({ rateBurst: 5, rateRefillPerSec: 50, maxRateViolations: 7 });
  const { ws, inbox } = await connect(srv, alice.cookie);
  await sleep(200);
  for (let round = 0; round < 2; round += 1) {
    for (let i = 0; i < 10; i += 1) send(ws, { type: "PING" });
    await sleep(300);
  }
  expect(rateErrors(inbox)).toHaveLength(2);
  expect(inbox.closed).toBeNull();
  ws.close();
});

describe("quarentena após 4429 (reconectar não zera o balde)", () => {
  test("padrão: 60 s", () => {
    expect(DEFAULT_LIMITS.rateLimitCooldownMs).toBe(60000);
  });

  test("o usuário derrubado por inundação não reabre conexão durante a quarentena (429)", async () => {
    await start({ rateBurst: 5, rateRefillPerSec: 1, maxRateViolations: 5, rateLimitCooldownMs: 400 });
    const bob = await loginUser(srv, "bob");
    const { ws, inbox } = await connect(srv, alice.cookie);
    for (let i = 0; i < 30; i += 1) send(ws, { type: "PING" });
    expect((await closed(inbox)).code).toBe(4429);

    const { openSocket } = require("./helpers");
    expect((await openSocket(srv, { cookie: alice.cookie })).status).toBe(429);
    // Outros usuários não são afetados.
    const other = await openSocket(srv, { cookie: bob.cookie });
    expect(other.ws).toBeDefined();
    other.ws.close();
    // Passada a quarentena, volta a conectar.
    await sleep(500);
    const again = await openSocket(srv, { cookie: alice.cookie });
    expect(again.ws).toBeDefined();
    again.ws.close();
  });
});
