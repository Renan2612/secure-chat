// O body é opaco e será texto cifrado na Etapa 4; o servidor não deve
// registrá-lo em log, nem os cookies ou quadros completos — em nenhum
// caminho, inclusive os de erro.
const { pool, resetDb, createRoomInDb, failQueriesMatching } = require("../helpers");
const { startServer, loginUser, connect, openSocket, nextPacket, closed, send } = require("./helpers");

const SECRET = "CONTEUDO-SECRETO-NAO-PODE-IR-PARA-O-LOG";

let srv;
let alice;
let bob;
let room;
let logged;

beforeEach(async () => {
  await resetDb();
  logged = [];
  for (const method of ["log", "info", "warn", "error", "debug"]) {
    jest.spyOn(console, method).mockImplementation((...args) => {
      logged.push(args.map((a) => (typeof a === "string" ? a : require("util").inspect(a, { depth: 5 }))).join(" "));
    });
  }
  srv = await startServer({ rateBurst: 8, maxRateViolations: 1000 });
  alice = await loginUser(srv, "alice");
  bob = await loginUser(srv, "bob");
  room = await createRoomInDb("Sala", [alice.id, bob.id]);
});
afterEach(async () => {
  jest.restoreAllMocks();
  await srv.stop();
});
afterAll(() => pool.end());

const expectCleanLogs = (...needles) => {
  for (const line of logged) {
    for (const needle of needles) expect(line).not.toContain(needle);
  }
};

test("fluxo normal, reenvio, sala alheia e pacotes inválidos: nada de body nem cookie no log", async () => {
  const other = await createRoomInDb("Outra", [bob.id]);
  const a = await connect(srv, alice.cookie);
  const b = await connect(srv, bob.cookie);
  send(b.ws, { type: "SUBSCRIBE", room });
  await nextPacket(b.inbox, "SUBSCRIBED");

  send(a.ws, { type: "MSG_SEND", room, cid: "c1", body: SECRET });
  await nextPacket(b.inbox, "MSG_DELIVER");
  send(a.ws, { type: "MSG_SEND", room, cid: "c1", body: SECRET }); // reenvio
  send(a.ws, { type: "MSG_SEND", room: other, cid: "c2", body: SECRET }); // NOT_MEMBER
  send(a.ws, { type: "MSG_SEND", room, cid: "c3", body: `${SECRET}${"x".repeat(9000)}` }); // grande demais
  a.ws.send(`{"v":1,"type":"MSG_SEND","body":"${SECRET}"`); // JSON inválido
  for (let i = 0; i < 4; i += 1) await nextPacket(a.inbox, i === 0 ? "MSG_ACK" : "ERROR");
  for (let i = 0; i < 6; i += 1) send(a.ws, { type: "MSG_SEND", room, cid: `f${i}`, body: SECRET }); // rate limit
  await new Promise((r) => setTimeout(r, 200));

  expectCleanLogs(SECRET, alice.cookie.split("=")[1], bob.cookie.split("=")[1]);
  [a, b].forEach(({ ws }) => ws.close());
});

test("erro interno ao gravar: o log tem o tipo do pacote, não o body", async () => {
  const injected = failQueriesMatching(/INSERT INTO messages/, new Error("falha simulada do banco"));
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "MSG_SEND", room, cid: "c1", body: SECRET, id: "r1" });
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "INTERNAL", ref: "r1" });
  expect(injected.count).toBe(1);
  expect(logged.join("\n")).toMatch(/MSG_SEND/);
  expectCleanLogs(SECRET, alice.cookie.split("=")[1]);
  ws.close();
});

test("quadro acima do maxPayload e falha no upgrade: nada do conteúdo no log", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  ws.send(SECRET.repeat(500));
  await closed(inbox);
  failQueriesMatching(/SELECT sess FROM/, new Error("store fora"));
  expect((await openSocket(srv, { cookie: alice.cookie })).status).toBe(503);
  expectCleanLogs(SECRET, alice.cookie.split("=")[1]);
});
