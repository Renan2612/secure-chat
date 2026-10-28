// Reenvio (ex.: o cliente não recebeu o MSG_ACK por queda de rede e manda
// de novo) não pode duplicar a mensagem: o cid identifica o envio.
const { pool, resetDb, createRoomInDb } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, send, expectNoPacket } = require("./helpers");

let srv;
let alice;
let bob;
let room;

beforeEach(async () => {
  await resetDb();
  srv = await startServer();
  alice = await loginUser(srv, "alice");
  bob = await loginUser(srv, "bob");
  room = await createRoomInDb("Sala", [alice.id, bob.id]);
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

const count = async () => Number((await pool.query("SELECT COUNT(*) FROM messages")).rows[0].count);

test("reenvio do mesmo cid não duplica: mesmo MSG_ACK, uma linha, uma entrega", async () => {
  const bobConn = await connect(srv, bob.cookie);
  send(bobConn.ws, { type: "SUBSCRIBE", room });
  await nextPacket(bobConn.inbox, "SUBSCRIBED");

  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "MSG_SEND", room, cid: "abc-123", body: "uma vez só" });
  const first = await nextPacket(inbox, "MSG_ACK");
  send(ws, { type: "MSG_SEND", room, cid: "abc-123", body: "uma vez só" });
  const second = await nextPacket(inbox, "MSG_ACK");

  expect(second).toEqual(first);
  expect(await count()).toBe(1);
  await nextPacket(bobConn.inbox, "MSG_DELIVER");
  await expectNoPacket(bobConn.inbox, "MSG_DELIVER");
  [ws, bobConn.ws].forEach((s) => s.close());
});

test("reenvio por outra conexão do mesmo usuário também não duplica", async () => {
  const c1 = await connect(srv, alice.cookie);
  const c2 = await connect(srv, alice.cookie);
  send(c1.ws, { type: "MSG_SEND", room, cid: "multi", body: "x" });
  const first = await nextPacket(c1.inbox, "MSG_ACK");
  send(c2.ws, { type: "MSG_SEND", room, cid: "multi", body: "x" });
  expect(await nextPacket(c2.inbox, "MSG_ACK")).toEqual(first);
  expect(await count()).toBe(1);
  [c1, c2].forEach(({ ws }) => ws.close());
});

test("reenvios simultâneos do mesmo cid gravam uma única vez", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  for (let i = 0; i < 5; i += 1) send(ws, { type: "MSG_SEND", room, cid: "rajada", body: "x" });
  const acks = [];
  for (let i = 0; i < 5; i += 1) acks.push(await nextPacket(inbox, "MSG_ACK"));
  expect(new Set(acks.map((a) => a.id)).size).toBe(1);
  expect(await count()).toBe(1);
  ws.close();
});

test("o cid é por usuário: o mesmo cid de outro usuário é outra mensagem", async () => {
  const a = await connect(srv, alice.cookie);
  const b = await connect(srv, bob.cookie);
  send(a.ws, { type: "MSG_SEND", room, cid: "1", body: "da alice" });
  send(b.ws, { type: "MSG_SEND", room, cid: "1", body: "do bob" });
  const ackA = await nextPacket(a.inbox, "MSG_ACK");
  const ackB = await nextPacket(b.inbox, "MSG_ACK");
  expect(ackA.id).not.toBe(ackB.id);
  expect(await count()).toBe(2);
  [a, b].forEach(({ ws }) => ws.close());
});

test("cids diferentes com o mesmo conteúdo são mensagens diferentes", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "MSG_SEND", room, cid: "a", body: "igual" });
  send(ws, { type: "MSG_SEND", room, cid: "b", body: "igual" });
  await nextPacket(inbox, "MSG_ACK");
  await nextPacket(inbox, "MSG_ACK");
  expect(await count()).toBe(2);
  ws.close();
});

test("mesmo cid em outra sala → ERROR CID_REUSED, nada gravado nem entregue", async () => {
  const other = await createRoomInDb("Outra", [alice.id]);
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "MSG_SEND", room, cid: "k", body: "x" });
  await nextPacket(inbox, "MSG_ACK");
  send(ws, { type: "MSG_SEND", room: other, cid: "k", body: "y", id: "r" });
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "CID_REUSED", ref: "r" });
  expect(await count()).toBe(1);
  ws.close();
});

test("reenvio de quem saiu da sala é rejeitado (NOT_MEMBER), não reconhecido", async () => {
  const { ws, inbox } = await connect(srv, bob.cookie);
  send(ws, { type: "MSG_SEND", room, cid: "z", body: "x" });
  await nextPacket(inbox, "MSG_ACK");
  await pool.query("DELETE FROM rooms_users WHERE room = $1 AND user_id = $2", [room, bob.id]);
  send(ws, { type: "MSG_SEND", room, cid: "z", body: "x" });
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "NOT_MEMBER" });
  ws.close();
});

test("cid de uma sala que o usuário deixou, reusado em sala onde é membro → CID_REUSED (não NOT_MEMBER)", async () => {
  const other = await createRoomInDb("Outra", [alice.id]);
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "MSG_SEND", room, cid: "k", body: "x" });
  await nextPacket(inbox, "MSG_ACK");
  await pool.query("DELETE FROM rooms_users WHERE room = $1 AND user_id = $2", [room, alice.id]);
  send(ws, { type: "MSG_SEND", room: other, cid: "k", body: "y" });
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "CID_REUSED" });
  ws.close();
});

test("não membro de uma sala recebe NOT_MEMBER mesmo reusando um cid seu de outra sala", async () => {
  const foreign = await createRoomInDb("Alheia", [bob.id]);
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "MSG_SEND", room, cid: "k", body: "x" });
  await nextPacket(inbox, "MSG_ACK");
  send(ws, { type: "MSG_SEND", room: foreign, cid: "k", body: "y" });
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "NOT_MEMBER" });
  ws.close();
});
