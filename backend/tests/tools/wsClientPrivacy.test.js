// ws-client e a privacidade (Etapa 5, A5): /ttl, /retention, /bans,
// /unban, /rename, nome da sala cifrado e mensagens que expiram na tela.
const path = require("path");
const { spawn } = require("child_process");
const e2ee = require("../../../shared/e2ee");
const { pool, resetDb, PASSWORD } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, send, ORIGIN } = require("../ws/helpers");
const { asCookie, registerKeys, join, fetchRoomKey } = require("../e2ee/flow");
const { clientSetup } = require("./clientEnv");

const CLIENT = path.join(__dirname, "..", "..", "tools", "ws-client.js");
const ROOM_NAME = "Sala Privada Do Grupo";

let srv;
let alice;
let bob;
let child;

beforeEach(async () => {
  await resetDb();
  srv = await startServer();
  alice = await loginUser(srv, "alice");
  bob = await registerKeys(asCookie(srv, await loginUser(srv, "bob")));
});
afterEach(async () => {
  if (child && child.exitCode === null) child.kill();
  await srv.stop();
});
afterAll(() => pool.end());

const run = (extraArgs) => {
  const setup = clientSetup();
  const httpUrl = srv.wsUrl.replace(/^ws/, "http").replace(/\/ws$/, "");
  child = spawn(process.execPath, [CLIENT, "--server", httpUrl, "--email", alice.email, "--origin", ORIGIN, ...setup.args, ...extraArgs], {
    env: { ...process.env, CHAT_PASSWORD: PASSWORD, ...setup.env },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const out = { stdout: "" };
  child.stdout.on("data", (d) => {
    out.stdout += d;
  });
  out.exited = new Promise((resolve) => child.on("exit", resolve));
  return out;
};

const waitUntil = async (check, label, timeoutMs = 8000) => {
  const start = Date.now();
  for (;;) {
    const value = check();
    if (value) return value;
    if (Date.now() - start > timeoutMs) throw new Error(`timeout esperando ${label}`);
    await new Promise((r) => setTimeout(r, 25));
  }
};

// Alice (ws-client) cria a sala com nome; Bob entra, é aprovado e fica
// inscrito por um WebSocket do teste.
const roomWithBob = async () => {
  const out = run(["--create-room", ROOM_NAME]);
  const [, id, invite] = await waitUntil(() => out.stdout.match(/sala criada: id (\d+); convite: ([0-9a-f]+)/), "sala criada");
  await waitUntil(() => /inscrito na sala/.test(out.stdout), "inscrição");
  const room = { roomId: Number(id), inviteKey: invite };
  await join(bob, room);
  await waitUntil(() => out.stdout.includes(`/approve ${bob.id}`), "anúncio do pendente");
  child.stdin.write(`/approve ${bob.id}\n`);
  await waitUntil(() => /chave da sala entregue a usuário/.test(out.stdout), "entrega");
  room.roomKey = await fetchRoomKey(bob, room.roomId);
  const b = await connect(srv, bob.cookie);
  send(b.ws, { type: "SUBSCRIBE", room: room.roomId });
  await nextPacket(b.inbox, "SUBSCRIBED");
  return { out, room, b };
};

const lastStored = async (roomId) =>
  (await pool.query("SELECT message, expires_at FROM messages WHERE room = $1 ORDER BY id DESC LIMIT 1", [roomId])).rows[0];

test("nome da sala: só cifrado no banco; a Alice o vê decifrado", async () => {
  const { out, room, b } = await roomWithBob();
  await waitUntil(() => out.stdout.includes(`«${ROOM_NAME}»`), "nome decifrado na tela");
  const { name_env: nameEnv } = (await pool.query("SELECT name_env FROM rooms WHERE id = $1", [room.roomId])).rows[0];
  expect(nameEnv).not.toContain("Privada");
  expect(await e2ee.decryptRoomName({ roomId: room.roomId, nameEnv, roomKeys: { 1: room.roomKey } })).toBe(ROOM_NAME);
  b.ws.close();
  child.stdin.end();
  expect(await out.exited).toBe(0);
}, 20000);

test("/ttl: as próximas mensagens levam exp assinado (minuto cheio); /ttl off volta a null; preset inválido mostra o uso", async () => {
  const { out, room, b } = await roomWithBob();
  child.stdin.write("/ttl 2h\n");
  await waitUntil(() => /uso: \/ttl/.test(out.stdout), "uso do /ttl");
  child.stdin.write("/ttl 1h\n");
  await waitUntil(() => /expiração das próximas mensagens: 3600 s/.test(out.stdout), "ttl ligado");
  const before = Math.floor(Date.now() / 1000);
  child.stdin.write("efemera\n");
  const deliver = await nextPacket(b.inbox, "MSG_DELIVER");
  const { exp } = JSON.parse(deliver.body);
  expect(exp % 60).toBe(0);
  expect(exp).toBeGreaterThanOrEqual(before + 3600);
  expect(exp).toBeLessThanOrEqual(before + 3600 + 61);
  expect((await lastStored(room.roomId)).expires_at.getTime()).toBe(exp * 1000);
  child.stdin.write("/ttl off\nperene\n");
  const second = await nextPacket(b.inbox, "MSG_DELIVER");
  expect(JSON.parse(second.body).exp).toBeNull();
  b.ws.close();
  child.stdin.end();
  expect(await out.exited).toBe(0);
}, 20000);

test("/retention: a dona define; sem /ttl a mensagem sai com exp até a retenção; ROOM_EVENT chega aos inscritos", async () => {
  const { out, room, b } = await roomWithBob();
  child.stdin.write("/retention 60\n");
  await waitUntil(() => /retenção da sala \d+: 60 s/.test(out.stdout), "retenção");
  expect(await nextPacket(b.inbox, "ROOM_EVENT")).toMatchObject({ kind: "RETENTION_CHANGED", retentionSeconds: 60 });
  expect((await pool.query("SELECT retention_seconds FROM rooms WHERE id = $1", [room.roomId])).rows[0].retention_seconds).toBe(60);
  const before = Math.floor(Date.now() / 1000);
  child.stdin.write("com retencao\n");
  const { exp } = JSON.parse((await nextPacket(b.inbox, "MSG_DELIVER")).body);
  expect(exp).toBeGreaterThanOrEqual(before + 60);
  expect(exp).toBeLessThanOrEqual(before + 121);
  // Um /ttl maior que a retenção é limitado por ela.
  child.stdin.write("/ttl 7d\n");
  await waitUntil(() => /a retenção da sala limita a 60 s/.test(out.stdout), "limite");
  child.stdin.write("/retention 10\n");
  await waitUntil(() => /uso: \/retention|retenção inválida/.test(out.stdout), "retenção inválida");
  child.stdin.write("/retention off\n");
  await waitUntil(() => /retenção da sala \d+: sem expiração/.test(out.stdout), "retenção desligada");
  b.ws.close();
  child.stdin.end();
  expect(await out.exited).toBe(0);
}, 20000);

test("/rename: o nome novo vai cifrado; o Bob (com a chave) lê, o servidor não", async () => {
  const { out, room, b } = await roomWithBob();
  child.stdin.write("/rename Nome Novo Secreto\n");
  await waitUntil(() => /renomeada/.test(out.stdout), "renomeada");
  expect(await nextPacket(b.inbox, "ROOM_EVENT")).toMatchObject({ kind: "RENAMED" });
  const [listed] = (await bob.call("get", "/rooms")).body;
  expect(listed.nameEnv).not.toContain("Secreto");
  expect(await e2ee.decryptRoomName({ roomId: room.roomId, nameEnv: listed.nameEnv, roomKeys: { 1: room.roomKey } })).toBe("Nome Novo Secreto");
  b.ws.close();
  child.stdin.end();
  expect(await out.exited).toBe(0);
}, 20000);

test("/kick, /bans e /unban; a rotação leva o nome recifrado com a chave nova", async () => {
  const { out, room, b } = await roomWithBob();
  child.stdin.write(`/kick ${bob.id}\n`);
  await waitUntil(() => /chave da sala \d+ trocada \(v2\)/.test(out.stdout), "rotação");
  const { name_env: nameEnv } = (await pool.query("SELECT name_env FROM rooms WHERE id = $1", [room.roomId])).rows[0];
  expect(e2ee.parseRoomNameEnvelope(nameEnv)).toEqual({ kv: 2 });
  // O removido, com a chave v1, não lê o nome novo.
  await expect(e2ee.decryptRoomName({ roomId: room.roomId, nameEnv, roomKeys: { 1: room.roomKey } })).rejects.toThrow(e2ee.E2eeError);
  child.stdin.write("/bans\n");
  await waitUntil(() => new RegExp(`banidos da sala \\d+:\\n  ${bob.id} bob`).test(out.stdout), "lista de banidos");
  child.stdin.write(`/unban ${bob.id}\n`);
  await waitUntil(() => new RegExp(`usuário ${bob.id} desbanido`).test(out.stdout), "desbanido");
  child.stdin.write(`/unban ${bob.id}\n/bans\n`);
  await waitUntil(() => /não está banido/.test(out.stdout) && /ninguém banido/.test(out.stdout), "nada mais banido");
  b.ws.close();
  child.stdin.end();
  expect(await out.exited).toBe(0);
}, 20000);

test("mensagem recebida com exp: mostra quando expira e é esquecida ao vencer", async () => {
  const { out, room, b } = await roomWithBob();
  // 3 s no futuro: dentro da tolerância de relógio do servidor (5 min).
  const exp = Math.floor(Date.now() / 1000) + 3;
  const cid = "efemera-do-bob";
  const body = await e2ee.encryptMessage({ roomKey: room.roomKey, kv: 1, roomId: room.roomId, senderId: bob.id, cid, text: "some logo", senderEcdsaKey: bob.identity.ecdsa.privateKey, exp });
  send(b.ws, { type: "MSG_SEND", room: room.roomId, cid, body });
  const ack = await nextPacket(b.inbox, "MSG_ACK");
  await waitUntil(() => /\[expira [0-9T:.-]+Z\]: some logo/.test(out.stdout), "mensagem com expiração");
  await waitUntil(() => new RegExp(`mensagem ${ack.id} expirou: removida da memória`).test(out.stdout), "esquecida", 8000);
  b.ws.close();
  child.stdin.end();
  expect(await out.exited).toBe(0);
}, 20000);
