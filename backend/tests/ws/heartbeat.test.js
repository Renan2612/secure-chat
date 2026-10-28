// Conexões mortas (cliente sumiu sem fechar o TCP) e sessões que terminam
// fora do logout (expiraram ou foram apagadas do store) não podem manter um
// socket vivo indefinidamente.
const { pool, resetDb } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, closed, send } = require("./helpers");
const { DEFAULT_LIMITS } = require("../../realtime/protocol");

let srv;
let alice;
const INTERVAL = 150;

beforeEach(async () => {
  await resetDb();
  srv = await startServer({ heartbeatIntervalMs: INTERVAL });
  alice = await loginUser(srv, "alice");
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test("padrão: heartbeat a cada 30 s", () => {
  expect(DEFAULT_LIMITS.heartbeatIntervalMs).toBe(30000);
});

test("o servidor envia ping de controle (RFC 6455) periodicamente", async () => {
  const { ws } = await connect(srv, alice.cookie);
  const ping = new Promise((resolve) => ws.once("ping", resolve));
  await expect(ping).resolves.toBeDefined();
  ws.close();
});

test("cliente que responde aos pings continua conectado", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  await sleep(INTERVAL * 5);
  expect(inbox.closed).toBeNull();
  send(ws, { type: "PING" });
  await nextPacket(inbox, "PONG");
  ws.close();
});

test("cliente que não responde ao ping (conexão morta) é encerrado e sai do registro", async () => {
  const { inbox } = await connect(srv, alice.cookie, { autoPong: false });
  // terminate(): sem handshake de fechamento, o cliente vê 1006.
  expect((await closed(inbox, INTERVAL * 6)).code).toBe(1006);
  await sleep(50);
  expect(srv.realtime.registry.countForUser(alice.id)).toBe(0);
});

test("sessão apagada do store fora do logout → close 4401 no próximo ciclo", async () => {
  const { inbox } = await connect(srv, alice.cookie);
  await pool.query("DELETE FROM user_sessions");
  expect((await closed(inbox, INTERVAL * 6)).code).toBe(4401);
});

test("sessão expirada → close 4401", async () => {
  const { inbox } = await connect(srv, alice.cookie);
  await pool.query("UPDATE user_sessions SET expire = NOW() - INTERVAL '1 minute'");
  expect((await closed(inbox, INTERVAL * 6)).code).toBe(4401);
});
