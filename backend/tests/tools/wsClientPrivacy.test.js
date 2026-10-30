// ws-client e a privacidade (Etapa 5, A5): /ttl, /retention, /bans,
// /unban, /rename, nome da sala cifrado e mensagens que expiram na tela.
const path = require("path");
const { spawn } = require("child_process");
const e2ee = require("../../../shared/e2ee");
const { pool, resetDb, PASSWORD } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, send, ORIGIN } = require("../ws/helpers");
const { asCookie, registerKeys, join, grant, fetchRoomKey, wrapFor, sealName, createKeyedRoom } = require("../e2ee/flow");
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
  expect(await e2ee.decryptRoomName({ roomId: room.roomId, nameEnv, roomKeys: { 1: room.roomKey } })).toMatchObject({ name: ROOM_NAME, seq: 1, ownerId: alice.id });
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
  expect(await e2ee.decryptRoomName({ roomId: room.roomId, nameEnv: listed.nameEnv, roomKeys: { 1: room.roomKey } })).toMatchObject({ name: "Nome Novo Secreto", seq: 2, ownerId: alice.id });
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

// --- nome assinado pelo dono (correção do docs/06 §4.6) ---------------------

// Bob (teste, com a chave atual) rotaciona: chave nova, wraps para os dois e
// o nome que ELE escolher (null = sem nome).
const rotateAs = async (user, room, version, recipients, nameEnvOf) => {
  const roomKey = await e2ee.generateRoomKey();
  const commitment = await e2ee.commitRoomKey({ roomId: room.roomId, version, roomKey, creatorEcdsaKey: user.identity.ecdsa.privateKey });
  const wraps = [];
  for (const r of recipients) {
    const wrap = await wrapFor(user, { roomId: room.roomId, version, roomKey, recipientId: r.id, recipientEcdhPub: r.ecdhPub });
    wraps.push({ recipientId: r.id, recipientKeyEpoch: r.keyEpoch, wrap });
  }
  const res = await user.call("post", `/rooms/${room.roomId}/keys/rotate`).send({ version, ...commitment, wraps, nameEnv: await nameEnvOf(roomKey) });
  expect(res.status).toBe(201);
  return roomKey;
};
const directoryKeys = async (userId) => ({ id: userId, ...(await bob.call("get", `/keys/${userId}`)).body });

test("ATAQUE: não-dono rotaciona com OUTRO nome (assinado por ele) → a Alice o rejeita, mantém o verificado e avisa", async () => {
  const { out, room, b } = await roomWithBob();
  await waitUntil(() => out.stdout.includes(`«${ROOM_NAME}»`), "nome verificado");
  // A v2 de um rotacionador só é aceita se ele for VERIFICADO (regra da 4b-2).
  child.stdin.write(`/safety ${bob.id}\n/trust ${bob.id}\n`);
  await waitUntil(() => new RegExp(`usuário ${bob.id} marcado como verificado`).test(out.stdout), "Bob verificado");
  const recipients = [await directoryKeys(alice.id), { id: bob.id, ecdhPub: bob.pub.ecdhPub, keyEpoch: bob.keyEpoch }];
  await rotateAs(bob, room, 2, recipients, async (roomKey) => (await sealName(bob, { roomKey, roomId: room.roomId, kv: 2, name: "Sala do Bob", seq: 99 })).nameEnv);
  await waitUntil(() => /chave da sala \d+ disponível \(v2/.test(out.stdout), "v2");
  await waitUntil(() => /nome da sala \d+ alterado por quem não é o dono; mantido o último nome verificado/.test(out.stdout), "aviso");
  const after = out.stdout.slice(out.stdout.indexOf("disponível (v2"));
  expect(after).toContain(`«${ROOM_NAME}»`);
  expect(out.stdout).not.toContain("Sala do Bob");
  b.ws.close();
  child.stdin.end();
  expect(await out.exited).toBe(0);
}, 30000);

test("troca de dono: o nome do dono anterior fica 'não verificado' para os outros até o novo dono (ws-client) re-assinar com seq + 1", async () => {
  // Bob (teste) é o dono; a Alice (ws-client) entra e recebe a chave.
  const room = await createKeyedRoom(bob, ROOM_NAME);
  const out = run(["--room", String(room.roomId), "--join", room.inviteKey]);
  await waitUntil(() => /inscrito na sala/.test(out.stdout), "inscrição");
  await waitUntil(() => /aguardando um membro entregá-la/.test(out.stdout), "sem chave");
  const aliceKeys = await directoryKeys(alice.id);
  expect((await grant(bob, room, { id: alice.id, pub: aliceKeys, keyEpoch: aliceKeys.keyEpoch })).status).toBe(201);
  await waitUntil(() => out.stdout.includes(`«${ROOM_NAME}»`), "nome verificado (assinado pelo Bob)");
  // Antes da re-assinatura, o nome assinado pelo Bob não vale para a Alice como dona.
  const stale = await e2ee.openRoomName({ nameEnv: (await bob.call("get", "/rooms")).body[0].nameEnv, roomKeys: { 1: room.roomKey }, roomId: room.roomId, ownerId: alice.id, ownerEcdsaPub: aliceKeys.ecdsaPub, last: room.namePayload });
  expect(stale).toMatchObject({ name: null, verified: false });
  expect((await bob.call("post", `/rooms/${room.roomId}/owner`).send({ userId: alice.id })).status).toBe(200);
  await waitUntil(() => /nome re-assinado com a sua chave/.test(out.stdout), "re-assinatura");
  const [listed] = (await bob.call("get", "/rooms")).body;
  const now = await e2ee.openRoomName({ nameEnv: listed.nameEnv, roomKeys: { 1: room.roomKey }, roomId: room.roomId, ownerId: alice.id, ownerEcdsaPub: aliceKeys.ecdsaPub, last: room.namePayload });
  expect(now).toMatchObject({ name: ROOM_NAME, verified: true, remember: { seq: 2, ownerId: alice.id } });
  child.stdin.end();
  expect(await out.exited).toBe(0);
}, 30000);

test("rotação sem conteúdo assinado válido: a Alice mostra 'nome não verificado' e rotaciona SEM nome (fallback)", async () => {
  // Bob (dono) cria a sala, mas o nome foi assinado por OUTRA pessoa (Carol).
  const carol = await registerKeys(asCookie(srv, await loginUser(srv, "carol")));
  const room = await createKeyedRoom(bob, "qualquer");
  const forged = await sealName(carol, { roomKey: room.roomKey, roomId: room.roomId, name: "Nome da Carol", seq: 7 });
  await pool.query("UPDATE rooms SET name_env = $2 WHERE id = $1", [room.roomId, forged.nameEnv]);
  const out = run(["--room", String(room.roomId), "--join", room.inviteKey]);
  await waitUntil(() => /aguardando um membro entregá-la/.test(out.stdout), "sem chave");
  const aliceKeys = await directoryKeys(alice.id);
  expect((await grant(bob, room, { id: alice.id, pub: aliceKeys, keyEpoch: aliceKeys.keyEpoch })).status).toBe(201);
  await waitUntil(() => new RegExp(`Sala #${room.roomId} \\(nome não verificado\\)`).test(out.stdout), "fallback na tela");
  expect(out.stdout).not.toContain("Nome da Carol");
  child.stdin.write("/rotate\n");
  await waitUntil(() => /chave da sala \d+ trocada \(v2\)/.test(out.stdout), "rotação");
  expect((await pool.query("SELECT key_version, name_env FROM rooms WHERE id = $1", [room.roomId])).rows[0]).toEqual({ key_version: 2, name_env: null });
  child.stdin.end();
  expect(await out.exited).toBe(0);
}, 30000);
