// Ataques ao envio em tempo real (itens B e C do baseline): forjar o
// remetente, postar em sala alheia, continuar postando/recebendo depois de
// sair da sala e ler o fluxo de outra sala.
// (O teste de remetente forjado era do antigo POST /messages —
// messageSender.test.js — e renasce aqui sobre o MSG_SEND.)
const { pool, resetDb, createRoomInDb, addMember } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, send, expectNoPacket } = require("./helpers");

let srv;
let alice;
let bob;
let roomX;
let roomY;

beforeEach(async () => {
  await resetDb();
  srv = await startServer();
  alice = await loginUser(srv, "alice");
  bob = await loginUser(srv, "bob");
  roomX = await createRoomInDb("Sala X", [alice.id, bob.id]);
  roomY = await createRoomInDb("Sala Y", [alice.id]);
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

const subscribed = async (user, room) => {
  const conn = await connect(srv, user.cookie);
  send(conn.ws, { type: "SUBSCRIBE", room });
  await nextPacket(conn.inbox, "SUBSCRIBED");
  return conn;
};

const removeMember = (room, userId) =>
  pool.query("DELETE FROM rooms_users WHERE room = $1 AND user_id = $2", [room, userId]);

const storedMessages = async () =>
  (await pool.query("SELECT room, user_id, message FROM messages ORDER BY id")).rows;

test("membro envia: grava no banco e recebe MSG_ACK { cid, id, ts }", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "MSG_SEND", room: roomX, cid: "c-1", body: "olá" });
  const ack = await nextPacket(inbox, "MSG_ACK");
  expect(ack).toEqual({ v: 1, type: "MSG_ACK", cid: "c-1", id: expect.any(Number), ts: expect.any(String) });
  expect(await storedMessages()).toEqual([{ room: roomX, user_id: alice.id, message: "olá" }]);
  ws.close();
});

test("campo from forjado é ignorado: a mensagem sai com o usuário da sessão", async () => {
  const aliceConn = await subscribed(alice, roomX);
  const bobConn = await connect(srv, bob.cookie);
  send(bobConn.ws, {
    type: "MSG_SEND",
    room: roomX,
    cid: "forjada",
    body: "eu sou a alice",
    from: alice.id,
    user_id: alice.id,
    user: { id: alice.id },
  });
  await nextPacket(bobConn.inbox, "MSG_ACK");
  const delivered = await nextPacket(aliceConn.inbox, "MSG_DELIVER");
  expect(delivered).toEqual({
    v: 1,
    type: "MSG_DELIVER",
    room: roomX,
    id: expect.any(Number),
    from: bob.id,
    ts: expect.any(String),
    body: "eu sou a alice",
  });
  expect(await storedMessages()).toEqual([{ room: roomX, user_id: bob.id, message: "eu sou a alice" }]);
  [aliceConn, bobConn].forEach(({ ws }) => ws.close());
});

test("MSG_DELIVER vai para as conexões inscritas na sala, inclusive as do remetente", async () => {
  const aliceConn = await subscribed(alice, roomX);
  const bobConn = await subscribed(bob, roomX);
  send(bobConn.ws, { type: "MSG_SEND", room: roomX, cid: "c", body: "para todos" });
  const ack = await nextPacket(bobConn.inbox, "MSG_ACK");
  expect(await nextPacket(aliceConn.inbox, "MSG_DELIVER")).toMatchObject({ id: ack.id, from: bob.id });
  expect(await nextPacket(bobConn.inbox, "MSG_DELIVER")).toMatchObject({ id: ack.id, ts: ack.ts });
  [aliceConn, bobConn].forEach(({ ws }) => ws.close());
});

test("B inscrito na sala X NÃO recebe mensagens da sala Y", async () => {
  const bobConn = await subscribed(bob, roomX);
  const aliceConn = await subscribed(alice, roomY);
  send(aliceConn.ws, { type: "MSG_SEND", room: roomY, cid: "y1", body: "segredo da sala Y" });
  await nextPacket(aliceConn.inbox, "MSG_DELIVER");
  await expectNoPacket(bobConn.inbox, "MSG_DELIVER");
  [aliceConn, bobConn].forEach(({ ws }) => ws.close());
});

test("membro conectado mas não inscrito na sala não recebe a entrega", async () => {
  const bobConn = await connect(srv, bob.cookie);
  const aliceConn = await connect(srv, alice.cookie);
  send(aliceConn.ws, { type: "MSG_SEND", room: roomX, cid: "x1", body: "oi" });
  await nextPacket(aliceConn.inbox, "MSG_ACK");
  await expectNoPacket(bobConn.inbox, "MSG_DELIVER");
  [aliceConn, bobConn].forEach(({ ws }) => ws.close());
});

test("não membro: ERROR NOT_MEMBER e nada é gravado", async () => {
  const { ws, inbox } = await connect(srv, bob.cookie);
  send(ws, { type: "MSG_SEND", room: roomY, cid: "intruso", body: "intruso", id: "r1" });
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "NOT_MEMBER", ref: "r1" });
  expect(await storedMessages()).toEqual([]);
  ws.close();
});

test("sala inexistente recebe o mesmo NOT_MEMBER", async () => {
  const { ws, inbox } = await connect(srv, bob.cookie);
  send(ws, { type: "MSG_SEND", room: 999999, cid: "c", body: "oi" });
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "NOT_MEMBER" });
  ws.close();
});

test("MSG_SEND de quem foi removido da sala (já inscrito) é rejeitado", async () => {
  const bobConn = await subscribed(bob, roomX);
  await removeMember(roomX, bob.id);
  send(bobConn.ws, { type: "MSG_SEND", room: roomX, cid: "depois", body: "ainda estou aqui?" });
  expect(await nextPacket(bobConn.inbox, "ERROR")).toMatchObject({ code: "NOT_MEMBER" });
  expect(await storedMessages()).toEqual([]);
  bobConn.ws.close();
});

test("quem foi removido da sala deixa de receber, mesmo ainda inscrito", async () => {
  const bobConn = await subscribed(bob, roomX);
  const aliceConn = await subscribed(alice, roomX);
  await removeMember(roomX, bob.id);
  send(aliceConn.ws, { type: "MSG_SEND", room: roomX, cid: "c", body: "bob saiu" });
  await nextPacket(aliceConn.inbox, "MSG_DELIVER");
  await expectNoPacket(bobConn.inbox, "MSG_DELIVER");
  expect(srv.realtime.registry.subscribers(roomX)).not.toContain(
    srv.realtime.registry.forUser(bob.id)[0]
  );
  [aliceConn, bobConn].forEach(({ ws }) => ws.close());
});

test("ao entrar na sala depois, o novo membro pode enviar", async () => {
  const bobConn = await connect(srv, bob.cookie);
  await addMember(roomY, bob.id);
  send(bobConn.ws, { type: "MSG_SEND", room: roomY, cid: "c", body: "cheguei" });
  await expect(nextPacket(bobConn.inbox, "MSG_ACK")).resolves.toMatchObject({ cid: "c" });
  bobConn.ws.close();
});
