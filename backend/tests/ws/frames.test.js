// Abuso no nível do quadro: payload gigante, JSON inválido, quadros
// binários e insistência em mandar lixo.
const { pool, resetDb } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, closed, send } = require("./helpers");
const { DEFAULT_LIMITS } = require("../../realtime/protocol");

let srv;
let alice;

beforeEach(async () => {
  await resetDb();
  srv = await startServer();
  alice = await loginUser(srv, "alice");
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

test("padrões: maxPayload de 16 KB e fechamento no 3º pacote inválido", () => {
  expect(DEFAULT_LIMITS.maxPayloadBytes).toBe(16 * 1024);
  expect(DEFAULT_LIMITS.maxInvalidPackets).toBe(3);
});

test("quadro acima do limite → close 1009", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  ws.send("x".repeat(DEFAULT_LIMITS.maxPayloadBytes + 1));
  expect((await closed(inbox)).code).toBe(1009);
});

test("quadro acima do limite antes do HELLO também → close 1009", async () => {
  const { openSocket } = require("./helpers");
  const { ws, inbox } = await openSocket(srv, { cookie: alice.cookie });
  ws.send("x".repeat(DEFAULT_LIMITS.maxPayloadBytes + 1));
  expect((await closed(inbox)).code).toBe(1009);
});

test("quadro exatamente no limite não é fechado por tamanho", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  ws.send(JSON.stringify({ v: 1, type: "PING", pad: "x".repeat(DEFAULT_LIMITS.maxPayloadBytes - 40) }).padEnd(DEFAULT_LIMITS.maxPayloadBytes, " "));
  await nextPacket(inbox, "PONG");
  expect(inbox.closed).toBeNull();
  ws.close();
});

test("JSON inválido → ERROR BAD_REQUEST, conexão segue aberta", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  ws.send("{isto não é json");
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ v: 1, code: "BAD_REQUEST" });
  send(ws, { type: "PING" });
  await nextPacket(inbox, "PONG");
  ws.close();
});

test("quadro binário → ERROR BAD_REQUEST (o protocolo só usa texto)", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  ws.send(Buffer.from(JSON.stringify({ v: 1, type: "PING" })), { binary: true });
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "BAD_REQUEST" });
  ws.close();
});

test("tipo desconhecido → ERROR BAD_REQUEST", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "BROADCAST_ALL", body: "oi" });
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "BAD_REQUEST" });
  ws.close();
});

test("reincidência: no 3º pacote inválido → ERROR e close 1008", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  ws.send("lixo 1");
  ws.send("lixo 2");
  await nextPacket(inbox, "ERROR");
  await nextPacket(inbox, "ERROR");
  expect(inbox.closed).toBeNull();
  ws.send("lixo 3");
  await nextPacket(inbox, "ERROR");
  expect((await closed(inbox)).code).toBe(1008);
});

test("erros de autorização (NOT_MEMBER) não contam como pacote inválido", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  for (let i = 0; i < 4; i += 1) {
    send(ws, { type: "SUBSCRIBE", room: 999999 });
    await nextPacket(inbox, "ERROR");
  }
  send(ws, { type: "PING" });
  await nextPacket(inbox, "PONG");
  expect(inbox.closed).toBeNull();
  ws.close();
});
