// Handshake de aplicação: o cliente tem um prazo para se apresentar (HELLO)
// com uma versão de protocolo suportada; nada é processado antes disso.
const { pool, resetDb } = require("../helpers");
const { startServer, loginUser, openSocket, connect, nextPacket, closed, send } = require("./helpers");

let srv;
let alice;

beforeEach(async () => {
  await resetDb();
  srv = await startServer({ helloTimeoutMs: 300 });
  alice = await loginUser(srv, "alice");
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

test("HELLO válido → WELCOME com versão, usuário da sessão, hora do servidor e limites", async () => {
  const { welcome, ws } = await connect(srv, alice.cookie);
  expect(welcome).toEqual({
    v: 1,
    type: "WELCOME",
    userId: alice.id,
    serverTime: expect.any(String),
    limits: expect.objectContaining({ maxPayloadBytes: expect.any(Number), maxBodyBytes: expect.any(Number) }),
  });
  expect(Math.abs(Date.parse(welcome.serverTime) - Date.now())).toBeLessThan(5000);
  ws.close();
});

test("sem HELLO dentro do prazo → close 4408", async () => {
  const { inbox } = await openSocket(srv, { cookie: alice.cookie });
  expect((await closed(inbox)).code).toBe(4408);
});

test("prazo padrão do HELLO é 5 s", () => {
  const { DEFAULT_LIMITS } = require("../../realtime/protocol");
  expect(DEFAULT_LIMITS.helloTimeoutMs).toBe(5000);
});

test("versão incompatível → ERROR UNSUPPORTED_VERSION e close 4426", async () => {
  const { ws, inbox } = await openSocket(srv, { cookie: alice.cookie });
  ws.send(JSON.stringify({ v: 2, type: "HELLO", client: "futuro" }));
  const error = await nextPacket(inbox, "ERROR");
  expect(error).toMatchObject({ v: 1, type: "ERROR", code: "UNSUPPORTED_VERSION" });
  expect((await closed(inbox)).code).toBe(4426);
});

test("pacote antes do HELLO → ERROR HELLO_REQUIRED e close 1008", async () => {
  const { ws, inbox } = await openSocket(srv, { cookie: alice.cookie });
  send(ws, { type: "SUBSCRIBE", room: 1 });
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "HELLO_REQUIRED" });
  expect((await closed(inbox)).code).toBe(1008);
});

test("HELLO repetido → ERROR BAD_REQUEST, conexão segue aberta", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "HELLO", client: "jest", id: "h2" });
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "BAD_REQUEST", ref: "h2" });
  send(ws, { type: "PING" });
  expect(await nextPacket(inbox, "PONG")).toMatchObject({ v: 1, type: "PONG" });
  ws.close();
});

test("PING → PONG", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "PING", id: "p1" });
  expect(await nextPacket(inbox, "PONG")).toEqual({ v: 1, type: "PONG", ref: "p1" });
  ws.close();
});
