// Ataque: o canal em tempo real sobrevive ao fim da sessão. Depois do
// logout, quem tinha um socket aberto (ex.: computador compartilhado)
// continuaria recebendo e enviando mensagens.
const { pool, resetDb, createRoomInDb } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, closed, send, openSocket } = require("./helpers");

let srv;
let alice;
let bob;

beforeEach(async () => {
  await resetDb();
  srv = await startServer();
  alice = await loginUser(srv, "alice");
  bob = await loginUser(srv, "bob");
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

test("após logout, a conexão aberta é fechada com 4401", async () => {
  const { inbox } = await connect(srv, alice.cookie);
  const res = await srv.http.post("/logout").set("Cookie", alice.cookie);
  expect(res.status).toBe(204);
  expect((await closed(inbox)).code).toBe(4401);
});

test("logout fecha TODAS as conexões do usuário, inclusive de outras sessões e antes do HELLO", async () => {
  const otherLogin = await srv.http.post("/login").send({ email: alice.email, password: require("../helpers").PASSWORD });
  const otherCookie = otherLogin.headers["set-cookie"].find((c) => c.startsWith("sid=")).split(";")[0];
  const c1 = await connect(srv, alice.cookie);
  const c2 = await connect(srv, otherCookie);
  const c3 = await openSocket(srv, { cookie: alice.cookie });
  await srv.http.post("/logout").set("Cookie", alice.cookie);
  for (const { inbox } of [c1, c2, c3]) expect((await closed(inbox)).code).toBe(4401);
});

test("conexões de outros usuários não são afetadas", async () => {
  const a = await connect(srv, alice.cookie);
  const b = await connect(srv, bob.cookie);
  await srv.http.post("/logout").set("Cookie", alice.cookie);
  await closed(a.inbox);
  send(b.ws, { type: "PING" });
  await nextPacket(b.inbox, "PONG");
  expect(b.inbox.closed).toBeNull();
  b.ws.close();
});

test("depois do logout, nada enviado pelo socket antigo é gravado", async () => {
  const room = await createRoomInDb("Sala", [alice.id]);
  const { ws, inbox } = await connect(srv, alice.cookie);
  await srv.http.post("/logout").set("Cookie", alice.cookie);
  await closed(inbox);
  expect(() => send(ws, { type: "MSG_SEND", room, cid: "c", body: "fantasma" })).not.toThrow();
  await new Promise((r) => setTimeout(r, 100));
  expect((await pool.query("SELECT 1 FROM messages")).rowCount).toBe(0);
});

test("quadro que chegue depois do close (cliente que ignora o fechamento) não é processado", async () => {
  const room = await createRoomInDb("Sala", [alice.id]);
  const { inbox } = await connect(srv, alice.cookie);
  const [serverConn] = srv.realtime.registry.forUser(alice.id);
  await srv.http.post("/logout").set("Cookie", alice.cookie);
  await closed(inbox);
  // Simula o quadro de um cliente que não respeita o close: entregue
  // direto à conexão do lado do servidor, que está em CLOSING.
  serverConn.onFrame(Buffer.from(JSON.stringify({ v: 1, type: "MSG_SEND", room, cid: "c", body: "pós-logout" })), false);
  await new Promise((r) => setTimeout(r, 100));
  expect((await pool.query("SELECT 1 FROM messages")).rowCount).toBe(0);
});

test("upgrade em andamento durante o logout não sobrevive a ele (corrida TOCTOU)", async () => {
  // Atrasa só a leitura da sessão feita pelo upgrade; o logout acontece
  // nesse intervalo, depois de a sessão ter sido lida como válida.
  const realQuery = pool.query.bind(pool);
  let release;
  const gate = new Promise((r) => {
    release = r;
  });
  let delayed = false;
  const spy = jest.spyOn(pool, "query").mockImplementation(async (text, ...rest) => {
    const sql = typeof text === "string" ? text : text?.text;
    if (!delayed && /SELECT sess FROM/.test(sql || "")) {
      delayed = true;
      const result = await realQuery(text, ...rest);
      await gate;
      return result;
    }
    return realQuery(text, ...rest);
  });
  const pending = openSocket(srv, { cookie: alice.cookie });
  while (!delayed) await new Promise((r) => setTimeout(r, 5));
  await srv.http.post("/logout").set("Cookie", alice.cookie);
  release();
  const res = await pending;
  spy.mockRestore();
  if (res.ws) {
    expect((await closed(res.inbox)).code).toBe(4401);
  } else {
    expect(res.status).toBe(401);
  }
  expect(srv.realtime.registry.countForUser(alice.id)).toBe(0);
});
