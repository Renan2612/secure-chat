// Ataque (item B): usuário autenticado tenta se inscrever no fluxo em tempo
// real de uma sala da qual não é membro.
const { pool, resetDb, createRoomInDb, addMember } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, send } = require("./helpers");

let srv;
let alice;
let bob;
let aliceRoom;

beforeEach(async () => {
  await resetDb();
  srv = await startServer();
  alice = await loginUser(srv, "alice");
  bob = await loginUser(srv, "bob");
  aliceRoom = await createRoomInDb("Sala da Alice", [alice.id]);
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

test("B não consegue SUBSCRIBE em sala da qual não é membro", async () => {
  const { ws, inbox } = await connect(srv, bob.cookie);
  send(ws, { type: "SUBSCRIBE", room: aliceRoom, id: "s1" });
  expect(await nextPacket(inbox, "ERROR")).toEqual({
    v: 1,
    type: "ERROR",
    code: "NOT_MEMBER",
    message: expect.any(String),
    ref: "s1",
  });
  expect(srv.realtime.registry.subscribers(aliceRoom)).toHaveLength(0);
  ws.close();
});

test("sala inexistente recebe o mesmo erro (não revela quais IDs existem)", async () => {
  const { ws, inbox } = await connect(srv, bob.cookie);
  send(ws, { type: "SUBSCRIBE", room: 999999 });
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "NOT_MEMBER" });
  ws.close();
});

test("membro consegue SUBSCRIBE e recebe SUBSCRIBED", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "SUBSCRIBE", room: aliceRoom });
  expect(await nextPacket(inbox, "SUBSCRIBED")).toEqual({ v: 1, type: "SUBSCRIBED", room: aliceRoom });
  expect(srv.realtime.registry.subscribers(aliceRoom)).toHaveLength(1);
  ws.close();
});

test("ao virar membro, B consegue se inscrever", async () => {
  await addMember(aliceRoom, bob.id);
  const { ws, inbox } = await connect(srv, bob.cookie);
  send(ws, { type: "SUBSCRIBE", room: aliceRoom });
  expect(await nextPacket(inbox, "SUBSCRIBED")).toMatchObject({ room: aliceRoom });
  ws.close();
});

test("UNSUBSCRIBE remove a inscrição", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "SUBSCRIBE", room: aliceRoom });
  await nextPacket(inbox, "SUBSCRIBED");
  send(ws, { type: "UNSUBSCRIBE", room: aliceRoom });
  expect(await nextPacket(inbox, "UNSUBSCRIBED")).toEqual({ v: 1, type: "UNSUBSCRIBED", room: aliceRoom });
  expect(srv.realtime.registry.subscribers(aliceRoom)).toHaveLength(0);
  ws.close();
});

test("fechar a conexão remove as inscrições dela", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "SUBSCRIBE", room: aliceRoom });
  await nextPacket(inbox, "SUBSCRIBED");
  ws.close();
  await new Promise((r) => ws.once("close", r));
  await new Promise((r) => setTimeout(r, 50));
  expect(srv.realtime.registry.subscribers(aliceRoom)).toHaveLength(0);
});

test.each([
  ["sala como texto", { room: "1" }],
  ["sala negativa", { room: -1 }],
  ["sem sala", {}],
])("SUBSCRIBE com %s → ERROR BAD_REQUEST", async (_label, payload) => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "SUBSCRIBE", ...payload });
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "BAD_REQUEST" });
  ws.close();
});
