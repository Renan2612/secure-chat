// ROOM_EVENT (extensão do protocolo v1, D4): o servidor avisa quem pode
// agir — KEY_PENDING para inscritos que TÊM a chave quando há membro sem
// chave; KEY_READY para o destinatário quando o wrap dele chega. O aviso não
// carrega nenhum dado de chave: o cliente busca pela API HTTP.
const e2ee = require("../../../shared/e2ee");
const { pool, resetDb } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, send, expectNoPacket } = require("./helpers");
const { asCookie, registerKeys, createKeyedRoom, join, grant } = require("../e2ee/flow");

let srv;
let alice;
let bob;
let room;

const subscribed = async (user, roomId) => {
  const conn = await connect(srv, user.cookie);
  send(conn.ws, { type: "SUBSCRIBE", room: roomId });
  await nextPacket(conn.inbox, "SUBSCRIBED");
  return conn;
};

beforeEach(async () => {
  await resetDb();
  srv = await startServer();
  alice = await registerKeys(asCookie(srv, await loginUser(srv, "alice")));
  bob = await registerKeys(asCookie(srv, await loginUser(srv, "bob")));
  room = await createKeyedRoom(alice);
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

test("alguém entra na sala → KEY_PENDING para o inscrito que tem a chave", async () => {
  const a = await subscribed(alice, room.roomId);
  await join(bob, room);
  expect(await nextPacket(a.inbox, "ROOM_EVENT")).toEqual({ v: 1, type: "ROOM_EVENT", room: room.roomId, kind: "KEY_PENDING" });
  a.ws.close();
});

test("inscrito SEM a chave não recebe KEY_PENDING (não pode agir)", async () => {
  await join(bob, room);
  const b = await subscribed(bob, room.roomId);
  const carol = await registerKeys(asCookie(srv, await loginUser(srv, "carol")));
  await join(carol, room);
  await expectNoPacket(b.inbox, "ROOM_EVENT");
  b.ws.close();
});

test("wrap entregue → KEY_READY para as conexões do destinatário, mesmo sem SUBSCRIBE", async () => {
  await join(bob, room);
  const b = await connect(srv, bob.cookie);
  expect((await grant(alice, room, bob)).status).toBe(201);
  expect(await nextPacket(b.inbox, "ROOM_EVENT")).toEqual({ v: 1, type: "ROOM_EVENT", room: room.roomId, kind: "KEY_READY" });
  b.ws.close();
});

test("KEY_READY não vai para outros usuários", async () => {
  const a = await subscribed(alice, room.roomId);
  await join(bob, room);
  await nextPacket(a.inbox, "ROOM_EVENT"); // o KEY_PENDING da entrada do Bob
  await grant(alice, room, bob);
  await expectNoPacket(a.inbox, "ROOM_EVENT");
  a.ws.close();
});

test("quem tem a chave e se inscreve com pendentes na sala recebe KEY_PENDING", async () => {
  await join(bob, room);
  const a = await subscribed(alice, room.roomId);
  expect(await nextPacket(a.inbox, "ROOM_EVENT")).toMatchObject({ room: room.roomId, kind: "KEY_PENDING" });
  a.ws.close();
});

test("sem pendentes, SUBSCRIBE não gera ROOM_EVENT", async () => {
  const a = await subscribed(alice, room.roomId);
  await expectNoPacket(a.inbox, "ROOM_EVENT");
  a.ws.close();
});

test("membro que troca as chaves (reset) volta a ser pendente → KEY_PENDING", async () => {
  await join(bob, room);
  await grant(alice, room, bob);
  const a = await subscribed(alice, room.roomId);
  await bob.call("post", "/keys/reset").send(await e2ee.exportPublicKeys(await e2ee.generateIdentity()));
  expect(await nextPacket(a.inbox, "ROOM_EVENT")).toMatchObject({ room: room.roomId, kind: "KEY_PENDING" });
  a.ws.close();
});

test("membro que entrou sem chave e depois registra chaves → KEY_PENDING", async () => {
  const carol = asCookie(srv, await loginUser(srv, "carol"));
  await join(carol, room);
  const a = await subscribed(alice, room.roomId);
  await nextPacket(a.inbox, "ROOM_EVENT"); // pendente desde a entrada (sem chaves ainda)
  await registerKeys(carol);
  expect(await nextPacket(a.inbox, "ROOM_EVENT")).toMatchObject({ room: room.roomId, kind: "KEY_PENDING" });
  a.ws.close();
});

describe("falha só no aviso não vira erro da operação (revisão \"errors\")", () => {
  afterEach(() => jest.restoreAllMocks());

  test("se a busca de pendentes falha depois do SUBSCRIBED, a inscrição segue sem ERROR", async () => {
    const { failQueriesMatching } = require("../helpers");
    await join(bob, room);
    jest.spyOn(console, "error").mockImplementation(() => {});
    const injected = failQueriesMatching(/FROM room_current_wraps WHERE room/, new Error("banco instável"));
    const a = await connect(srv, alice.cookie);
    send(a.ws, { type: "SUBSCRIBE", id: "s", room: room.roomId });
    await nextPacket(a.inbox, "SUBSCRIBED");
    await expectNoPacket(a.inbox, "ERROR");
    expect(injected.count).toBe(1);
    expect(a.inbox.closed).toBeNull();
    a.ws.close();
  });

  test("PUT /keys grava e responde 201 mesmo se o cálculo dos avisos falhar depois", async () => {
    const { failQueriesMatching } = require("../helpers");
    const carol = asCookie(srv, await loginUser(srv, "carol"));
    await join(carol, room);
    jest.spyOn(console, "error").mockImplementation(() => {});
    const injected = failQueriesMatching(/SELECT m\.room FROM rooms_users m/, new Error("banco instável"));
    carol.identity = await e2ee.generateIdentity();
    const res = await carol.call("put", "/keys").send(await e2ee.exportPublicKeys(carol.identity));
    expect(injected.count).toBe(1);
    expect(res.status).toBe(201);
  });
});
