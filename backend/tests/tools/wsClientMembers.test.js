// ws-client e a composição da sala (Etapa 4b-2, D4): rotação automática ao
// receber ROTATION_PENDING, /kick (remover + trocar a chave), /invite,
// /owner e /leave, e os eventos de sala na tela.
const path = require("path");
const { spawn } = require("child_process");
const { pool, resetDb, PASSWORD } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, ORIGIN } = require("../ws/helpers");
const { asCookie, registerKeys, join, fetchRoomKey } = require("../e2ee/flow");
const { clientSetup } = require("./clientEnv");

const CLIENT = path.join(__dirname, "..", "..", "tools", "ws-client.js");

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

// Alice (ws-client) cria a sala e aprova o Bob, que recebe a chave v1.
const roomWithBob = async () => {
  const out = run(["--create-room", "Sala"]);
  const [, id, invite] = await waitUntil(() => out.stdout.match(/sala criada: id (\d+); convite: ([0-9a-f]+)/), "sala criada");
  await waitUntil(() => /inscrito na sala/.test(out.stdout), "inscrição");
  const room = { roomId: Number(id), inviteKey: invite };
  await join(bob, room);
  await waitUntil(() => out.stdout.includes(`/approve ${bob.id}`), "anúncio do pendente");
  child.stdin.write(`/approve ${bob.id}\n`);
  await waitUntil(() => /chave da sala entregue a usuário/.test(out.stdout), "entrega");
  await fetchRoomKey(bob, room.roomId);
  return { out, room };
};

const v2Recipients = async (roomId) =>
  (await pool.query("SELECT recipient_id FROM room_key_wraps WHERE room = $1 AND version = 2", [roomId])).rows.map((r) => r.recipient_id);

test("Bob sai: o cliente da Alice mostra o evento e troca a chave sozinho (v2 só para quem ficou)", async () => {
  const { out, room } = await roomWithBob();
  expect((await bob.call("post", `/rooms/${room.roomId}/leave`)).status).toBe(200);
  await waitUntil(() => /evento: alguém saiu da sala/.test(out.stdout), "evento ROTATION_PENDING");
  await waitUntil(() => /chave da sala \d+ trocada \(v2\)/.test(out.stdout), "rotação automática");
  expect(await v2Recipients(room.roomId)).toEqual([alice.id]);
  expect((await pool.query("SELECT rotation_required FROM rooms WHERE id = $1", [room.roomId])).rows[0].rotation_required).toBe(false);
  child.stdin.end();
  expect(await out.exited).toBe(0);
}, 20000);

test("/kick: o removido recebe REMOVED; a Alice vê o convite novo uma vez e a chave trocada", async () => {
  const { out, room } = await roomWithBob();
  const b = await connect(srv, bob.cookie);
  child.stdin.write(`/kick ${bob.id}\n`);
  await waitUntil(() => /removido da sala \d+; convite novo \(mostrado só agora\): [0-9a-f]{32}/.test(out.stdout), "convite novo");
  await waitUntil(() => /chave da sala \d+ trocada \(v2\)/.test(out.stdout), "rotação");
  expect(await nextPacket(b.inbox, "ROOM_EVENT")).toMatchObject({ room: room.roomId, kind: "REMOVED" });
  expect(await v2Recipients(room.roomId)).toEqual([alice.id]);
  b.ws.close();
  child.stdin.end();
  expect(await out.exited).toBe(0);
}, 20000);

test("/invite, /owner e /leave", async () => {
  const { out, room } = await roomWithBob();
  child.stdin.write("/invite\n");
  const [, fresh] = await waitUntil(() => out.stdout.match(/convite novo da sala \d+ \(mostrado só agora; o anterior deixou de valer\): ([0-9a-f]{32})/), "convite");
  expect(fresh).not.toBe(room.inviteKey);
  child.stdin.write("/leave\n");
  await waitUntil(() => /transfira o cargo antes/.test(out.stdout), "recusa do /leave do dono");
  child.stdin.write(`/owner ${bob.id}\n`);
  await waitUntil(() => new RegExp(`usuário ${bob.id} agora é o dono`).test(out.stdout), "transferência");
  child.stdin.write("/leave\n");
  await waitUntil(() => /você saiu da sala \d+$/m.test(out.stdout), "saída");
  await out.exited;
  expect(out.stdout).not.toMatch(/não é mais membro/); // o REMOVED da própria saída é esperado
  expect((await pool.query("SELECT owner_id FROM rooms WHERE id = $1", [room.roomId])).rows[0].owner_id).toBe(bob.id);
}, 20000);

test("ROTATION_PENDING no envio é explicado; a mensagem não é enviada", async () => {
  const { out, room } = await roomWithBob();
  await pool.query("UPDATE rooms SET rotation_required = TRUE WHERE id = $1", [room.roomId]); // sem evento: o cliente não sabe
  child.stdin.write("olá\n");
  await waitUntil(() => /ROTATION_PENDING/.test(out.stdout) && /NÃO foi enviada/.test(out.stdout), "erro explicado");
  child.stdin.end();
  expect(await out.exited).toBe(1);
}, 20000);
