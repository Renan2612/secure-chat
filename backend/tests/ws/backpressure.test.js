// Ataque: cliente lento (ou que para de ler de propósito) faz o servidor
// acumular em memória tudo o que deveria entregar a ele.
const { pool, resetDb, createRoomInDb, fakeEnvelope } = require("../helpers");
// Etapa 4b: o servidor só aceita envelope E2EE v1. Estes testes não decifram
// nada, então cada rótulo vira um envelope estruturalmente válido (sempre o
// mesmo para o mesmo rótulo, para comparar com o que foi gravado/entregue).
const envs = new Map();
const env = (label) => {
  if (!envs.has(label)) envs.set(label, fakeEnvelope());
  return envs.get(label);
};
const { startServer, loginUser, connect, nextPacket, closed, send } = require("./helpers");
const { DEFAULT_LIMITS } = require("../../realtime/protocol");

let srv;
let alice;
let bob;
let room;

beforeEach(async () => {
  await resetDb();
  srv = await startServer({ maxBufferedBytes: 64 * 1024 });
  alice = await loginUser(srv, "alice");
  bob = await loginUser(srv, "bob");
  room = await createRoomInDb("Sala", [alice.id, bob.id]);
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

const subscribed = async (user) => {
  const conn = await connect(srv, user.cookie);
  send(conn.ws, { type: "SUBSCRIBE", room });
  await nextPacket(conn.inbox, "SUBSCRIBED");
  return conn;
};

// Simula o que acontece quando o cliente não lê: o buffer de saída do
// socket do lado do servidor cresce (o kernel do loopback absorveria muitos
// MB antes, o que deixaria o teste lento e instável).
const makeSlow = (userId, bytes) => {
  const [serverConn] = srv.realtime.registry.forUser(userId);
  Object.defineProperty(serverConn.socket, "bufferedAmount", { get: () => bytes });
};

test("padrão: 1 MB de buffer de saída por conexão", () => {
  expect(DEFAULT_LIMITS.maxBufferedBytes).toBe(1024 * 1024);
});

test("cliente com buffer de saída acima do limite é desconectado na próxima entrega", async () => {
  const slow = await subscribed(bob);
  const fast = await subscribed(alice);
  makeSlow(bob.id, 64 * 1024 + 1);
  send(fast.ws, { type: "MSG_SEND", room, cid: "c1", body: env("oi") });
  await nextPacket(fast.inbox, "MSG_DELIVER");
  await closed(slow.inbox);
  await new Promise((r) => setTimeout(r, 50));
  expect(slow.inbox.packets.filter((p) => p.type === "MSG_DELIVER")).toEqual([]);
  expect(srv.realtime.registry.countForUser(bob.id)).toBe(0);
  fast.ws.close();
});

test("buffer dentro do limite: entrega normal", async () => {
  const slowish = await subscribed(bob);
  const fast = await subscribed(alice);
  makeSlow(bob.id, 64 * 1024);
  send(fast.ws, { type: "MSG_SEND", room, cid: "c1", body: env("oi") });
  await nextPacket(slowish.inbox, "MSG_DELIVER");
  expect(slowish.inbox.closed).toBeNull();
  [slowish, fast].forEach(({ ws }) => ws.close());
});
