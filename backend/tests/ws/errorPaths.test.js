// Caminhos de erro do canal em tempo real: falhas do banco ou de código não
// podem derrubar o processo, mandar respostas contraditórias nem sumir sem
// registro (achados da revisão "errors").
const { pool, resetDb, createRoomInDb, failQueriesMatching } = require("../helpers");
const { startServer, loginUser, connect, openSocket, nextPacket, closed, send, expectNoPacket } = require("./helpers");

let srv;
let alice;
let bob;
let room;
let logged;

beforeEach(async () => {
  await resetDb();
  logged = [];
  jest.spyOn(console, "error").mockImplementation((...args) => logged.push(args.join(" ")));
  srv = await startServer({ heartbeatIntervalMs: 150 });
  alice = await loginUser(srv, "alice");
  bob = await loginUser(srv, "bob");
  room = await createRoomInDb("Sala", [alice.id, bob.id]);
});
afterEach(async () => {
  jest.restoreAllMocks();
  await srv.stop();
});
afterAll(() => pool.end());

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test("falha na entrega depois de gravar: remetente recebe só o MSG_ACK, sem ERROR INTERNAL; log próprio", async () => {
  const b = await connect(srv, bob.cookie);
  send(b.ws, { type: "SUBSCRIBE", room });
  await nextPacket(b.inbox, "SUBSCRIBED");
  const injected = failQueriesMatching(/SELECT user_id FROM rooms_users/, Object.assign(new Error("banco instável"), { code: "57P01" }));
  const a = await connect(srv, alice.cookie);
  send(a.ws, { type: "MSG_SEND", room, cid: "c1", body: "gravada", id: "r1" });
  await nextPacket(a.inbox, "MSG_ACK");
  await expectNoPacket(a.inbox, "ERROR");
  expect(injected.count).toBe(1);
  expect((await pool.query("SELECT 1 FROM messages")).rowCount).toBe(1);
  expect(logged.join("\n")).toMatch(/falha na entrega/);
  [a, b].forEach(({ ws }) => ws.close());
});

test("log de erro interno traz o código do erro (SQLSTATE), não só a mensagem", async () => {
  failQueriesMatching(/INSERT INTO messages/, Object.assign(new Error("x"), { code: "53300" }));
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "MSG_SEND", room, cid: "c1", body: "oi" });
  await nextPacket(inbox, "ERROR");
  expect(logged.join("\n")).toMatch(/MSG_SEND.*code=53300/);
  ws.close();
});

test("erro de protocolo da ws (quadro grande demais) é registrado com o código, sem conteúdo", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  ws.send("SEGREDO".repeat(5000));
  await closed(inbox);
  await sleep(50);
  const text = logged.join("\n");
  expect(text).toMatch(/\[ws\] erro de protocolo .*code=WS_ERR_UNSUPPORTED_MESSAGE_LENGTH/);
  expect(text).not.toContain("SEGREDO");
});

test("falha ao registrar a conexão depois do 101: socket derrubado, sem HTTP 503 no fluxo e sem vazar no registro", async () => {
  jest.spyOn(srv.realtime.registry, "add").mockImplementation(() => {
    throw new Error("falha simulada");
  });
  const res = await openSocket(srv, { cookie: alice.cookie });
  expect(res.ws).toBeDefined(); // o 101 já tinha saído
  const { code } = await closed(res.inbox);
  expect(code).toBe(1006);
  expect(logged.join("\n")).toMatch(/\[ws\] falha ao registrar conexão/);
  expect(srv.realtime.registry.size).toBe(0);
});

test("store de sessão fora do ar no heartbeat: conexões mantidas; quando volta, a revalidação funciona", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  const injected = failQueriesMatching(/SELECT sess FROM/, new Error("store fora"), Infinity);
  await sleep(600);
  expect(injected.count).toBeGreaterThan(0);
  expect(inbox.closed).toBeNull();
  send(ws, { type: "PING" });
  await nextPacket(inbox, "PONG");
  jest.restoreAllMocks();
  jest.spyOn(console, "error").mockImplementation(() => {});
  await pool.query("DELETE FROM user_sessions");
  expect((await closed(inbox, 1500)).code).toBe(4401);
});

test("se derrubar os sockets falhar no logout, o logout ainda responde 204 e o processo segue", async () => {
  srv.realtime.closeUser = () => {
    throw new Error("falha simulada");
  };
  const res = await srv.http.post("/logout").set("Cookie", alice.cookie);
  expect(res.status).toBe(204);
  expect(logged.join("\n")).toMatch(/\[logout\] falha ao encerrar/);
  expect((await srv.http.get("/rooms").set("Cookie", alice.cookie)).status).toBe(401);
});
