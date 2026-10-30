// Etapa 5 (A4): varredura de TUDO o que o backend escreve (console e
// stdout/stderr) durante um fluxo completo, inclusive os caminhos de erro
// (falha do banco no meio de rotas com corpo, JSON malformado, upgrade
// recusado, pacotes inválidos no /ws). Não pode aparecer: IP do cliente,
// e-mail, senha, cookie de sessão, body de mensagem nem nome de sala.
// O inventário do que É registrado está em docs/06-privacidade.md.
const util = require("util");
const e2ee = require("../../shared/e2ee");
const { pool, resetDb, failQueriesMatching, PASSWORD } = require("./helpers");
const { startServer, connect, openSocket, nextPacket, send } = require("./ws/helpers");
const { asCookie, registerKeys, createKeyedRoom, join, grant } = require("./e2ee/flow");

const ROOM_NAME = "NOME-DE-SALA-NAO-PODE-IR-PARA-O-LOG";
const TEXT = "TEXTO-DA-MENSAGEM-NAO-PODE-IR-PARA-O-LOG";
const CLIENT_IP = "203.0.113.77"; // TEST-NET-3: só aparece se alguém o registrar
const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/;

let logged;
let srv;

beforeEach(async () => {
  await resetDb();
  logged = [];
  for (const method of ["log", "info", "warn", "error", "debug"]) {
    jest.spyOn(console, method).mockImplementation((...args) => {
      logged.push(args.map((a) => (typeof a === "string" ? a : util.inspect(a, { depth: 5 }))).join(" "));
    });
  }
  for (const stream of [process.stdout, process.stderr]) {
    const realWrite = stream.write.bind(stream);
    jest.spyOn(stream, "write").mockImplementation((chunk, ...rest) => {
      logged.push(String(chunk));
      return realWrite(chunk, ...rest);
    });
  }
  srv = await startServer();
});
afterEach(async () => {
  jest.restoreAllMocks();
  await srv.stop();
});
afterAll(() => pool.end());

const register = async (name) => {
  const email = `${name}.privacidade@example.com`;
  await srv.http.post("/register").set("X-Forwarded-For", CLIENT_IP).send({ email, password: PASSWORD, name });
  const login = await srv.http.post("/login").set("X-Forwarded-For", CLIENT_IP).send({ email, password: PASSWORD });
  const cookie = login.headers["set-cookie"].find((c) => c.startsWith("sid=")).split(";")[0];
  return { id: login.body.id, email, cookie };
};

test("fluxo completo, com erros: nada de IP, e-mail, senha, cookie, body ou nome de sala no log", async () => {
  const alice = await registerKeys(asCookie(srv, await register("alice")));
  const bob = await registerKeys(asCookie(srv, await register("bob")));
  const room = await createKeyedRoom(alice, ROOM_NAME);
  await join(bob, room);
  await grant(alice, room, bob);
  const body = await e2ee.encryptMessage({ roomKey: room.roomKey, kv: 1, roomId: room.roomId, senderId: alice.id, cid: "c1", text: TEXT, senderEcdsaKey: alice.identity.ecdsa.privateKey });
  const a = await connect(srv, alice.cookie);
  send(a.ws, { type: "MSG_SEND", room: room.roomId, cid: "c1", body });
  await nextPacket(a.inbox, "MSG_ACK");

  // Caminhos de erro, com dados sensíveis na requisição.
  failQueriesMatching(/INSERT INTO users/, Object.assign(new Error("falha simulada"), { code: "XX000" }));
  await srv.http.post("/register").send({ email: "carol.privacidade@example.com", password: PASSWORD, name: "Carol" }); // 500
  jest.restoreAllMocks();
  for (const method of ["log", "info", "warn", "error", "debug"]) {
    jest.spyOn(console, method).mockImplementation((...args) => logged.push(args.map(String).join(" ")));
  }
  await srv.http.post("/register").send({ email: alice.email, password: PASSWORD, name: "Repetida" }); // 409 (e-mail repetido)
  await srv.http.post("/login").set("Content-Type", "application/json").send(`{"email":"${alice.email}","password":`); // JSON malformado
  await srv.http.post("/createRoom").set("Cookie", alice.cookie).send({ name: ROOM_NAME }); // nome em claro recusado
  await srv.http.post("/login").set("Origin", "https://evil.example").send({ email: alice.email, password: PASSWORD }); // CSRF
  send(a.ws, { type: "MSG_SEND", room: room.roomId, cid: "c2", body: TEXT }); // texto puro → E2EE_REQUIRED
  await nextPacket(a.inbox, "ERROR");
  a.ws.send(`{"v":1,"type":"MSG_SEND","body":"${TEXT}"`); // JSON inválido
  expect((await openSocket(srv, { cookie: alice.cookie, origin: "https://evil.example" })).status).toBe(403);
  a.ws.close();

  const text = logged.join("\n");
  // Controle positivo: a captura do log funciona (o erro simulado foi registrado).
  expect(text).toMatch(/falha simulada/);
  for (const forbidden of [
    alice.email,
    bob.email,
    "carol.privacidade@example.com",
    PASSWORD,
    alice.cookie.slice("sid=".length),
    bob.cookie.slice("sid=".length),
    ROOM_NAME,
    TEXT,
    JSON.parse(body).ct.slice(0, 32),
    CLIENT_IP,
  ]) {
    expect({ forbidden, found: text.includes(forbidden) }).toEqual({ forbidden, found: false });
  }
  expect(text).not.toMatch(IPV4);
});
