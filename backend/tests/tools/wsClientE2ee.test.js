// ws-client com E2EE (item 6): keystore cifrado, chaves registradas no
// diretório, criação da sala com a chave v1, entrega automática da chave a
// quem entra (conferindo o trust store), mensagens cifradas nos dois
// sentidos, número de segurança, /trust e CHAVE ALTERADA.
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const e2ee = require("../../../shared/e2ee");
const { pool, resetDb, PASSWORD } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, send, ORIGIN } = require("../ws/helpers");
const { asCookie, registerKeys, join, fetchRoomKey } = require("../e2ee/flow");
const { clientSetup, KEY_PASSPHRASE } = require("./clientEnv");

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

const run = (setup, extraArgs, env = {}) => {
  const httpUrl = srv.wsUrl.replace(/^ws/, "http").replace(/\/ws$/, "");
  child = spawn(process.execPath, [CLIENT, "--server", httpUrl, "--email", alice.email, "--origin", ORIGIN, ...setup.args, ...extraArgs], {
    env: { ...process.env, CHAT_PASSWORD: PASSWORD, ...setup.env, ...env },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const out = { child, stdout: "", stderr: "" };
  child.stdout.on("data", (d) => {
    out.stdout += d;
  });
  child.stderr.on("data", (d) => {
    out.stderr += d;
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

// Alice (ws-client) cria a sala; Bob (teste) entra com o convite e recebe
// a chave entregue AUTOMATICAMENTE pelo cliente da Alice.
const roomWithBob = async (setup = clientSetup()) => {
  const out = run(setup, ["--create-room", "Sala E2EE"]);
  const [, id, invite] = await waitUntil(() => out.stdout.match(/sala criada: id (\d+); convite: ([0-9a-f]+)/), "sala criada");
  await waitUntil(() => /inscrito na sala/.test(out.stdout), "inscrição");
  const room = { roomId: Number(id), inviteKey: invite };
  await join(bob, room);
  await waitUntil(() => /chave da sala entregue a usuário/.test(out.stdout), "entrega da chave");
  room.roomKey = await fetchRoomKey(bob, room.roomId);
  return { out, room, setup };
};

const bobSays = async (room, text, cid) => {
  const b = await connect(srv, bob.cookie);
  const body = await e2ee.encryptMessage({ roomKey: room.roomKey, kv: 1, roomId: room.roomId, senderId: bob.id, cid, text, senderEcdsaKey: bob.identity.ecdsa.privateKey });
  send(b.ws, { type: "MSG_SEND", room: room.roomId, cid, body });
  await nextPacket(b.inbox, "MSG_ACK");
  b.ws.close();
};

test("cria a sala, entrega a chave a quem entra e troca mensagens cifradas nos dois sentidos", async () => {
  const { out, room } = await roomWithBob();

  await bobSays(room, "olá do bob", "b1");
  await waitUntil(() => out.stdout.includes(`usuário ${bob.id} [não verificado]: olá do bob`), "mensagem do Bob decifrada");

  const b = await connect(srv, bob.cookie);
  send(b.ws, { type: "SUBSCRIBE", room: room.roomId });
  await nextPacket(b.inbox, "SUBSCRIBED");
  const marker = `MARCADOR-${Date.now()}`;
  child.stdin.write(`${marker}\n`);
  const deliver = await nextPacket(b.inbox, "MSG_DELIVER", 8000);
  const aliceKeys = (await bob.call("get", `/keys/${alice.id}`)).body;
  const text = await e2ee.decryptMessage({ body: deliver.body, roomKeys: { 1: room.roomKey }, roomId: deliver.room, senderId: deliver.from, cid: deliver.cid, senderEcdsaPub: aliceKeys.ecdsaPub });
  expect(text).toBe(marker);
  await waitUntil(() => /enviada/.test(out.stdout), "confirmação");

  const { rows: tables } = await pool.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public'");
  for (const { tablename } of tables) {
    const { rows } = await pool.query(`SELECT row_to_json(t)::text AS row FROM "${tablename}" t`);
    for (const { row } of rows) expect({ tablename, leaks: row.includes(marker) }).toEqual({ tablename, leaks: false });
  }
  child.stdin.end();
  expect(await out.exited).toBe(0);
  b.ws.close();
}, 30000);

test("keystore e trust store: 0600, cifrados (nenhuma chave privada em claro), fora do repositório", async () => {
  const { out, setup } = await roomWithBob();
  child.stdin.end();
  expect(await out.exited).toBe(0);
  for (const file of [setup.keystore, setup.keystore.replace(/\.json$/, ".trust.json")]) {
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    const sealed = JSON.parse(fs.readFileSync(file, "utf8"));
    expect(sealed).toMatchObject({ format: "secure-chat-keystore", kdf: { name: "PBKDF2-SHA-256" } });
    expect(fs.readFileSync(file, "utf8")).not.toMatch(/Priv|BEGIN|ecdh|ecdsa/i);
  }
  const opened = await require("../../../shared/e2ee/node").readSealedFile(setup.keystore, KEY_PASSPHRASE);
  expect(opened.userId).toBe(alice.id);
  expect(opened.identity.ecdsaPriv).toEqual(expect.any(String));
}, 30000);

test("segunda execução reabre o keystore: mesmas chaves (sem 409) e a chave da sala já guardada", async () => {
  const { out, room, setup } = await roomWithBob();
  child.stdin.end();
  await out.exited;
  const again = run(setup, ["--room", String(room.roomId)]);
  await waitUntil(() => /chave da sala \d+ disponível/.test(again.stdout), "chave guardada");
  child.stdin.end();
  expect(await again.exited).toBe(0);
}, 30000);

test("senha de cifragem errada: recusa abrir o keystore, sai com 1 e não o sobrescreve", async () => {
  const { out, room, setup } = await roomWithBob();
  child.stdin.end();
  await out.exited;
  const before = fs.readFileSync(setup.keystore, "utf8");
  const wrong = run(setup, ["--room", String(room.roomId)], { CHAT_KEY_PASSPHRASE: "outra-senha-qualquer" });
  expect(await wrong.exited).toBe(1);
  expect(wrong.stderr).toMatch(/senha de cifragem errada/);
  expect(fs.readFileSync(setup.keystore, "utf8")).toBe(before);
}, 30000);

test("senha de cifragem igual à senha de login é recusada", async () => {
  const out = run(clientSetup(), ["--create-room", "X"], { CHAT_KEY_PASSPHRASE: PASSWORD });
  expect(await out.exited).toBe(1);
  expect(out.stderr).toMatch(/diferente da senha de login/);
});

test("keystore dentro do repositório é recusado", async () => {
  const setup = clientSetup();
  const inside = path.join(__dirname, "keystore-proibido.json");
  const out = run({ ...setup, args: ["--keystore", inside] }, ["--create-room", "X"]);
  expect(await out.exited).toBe(1);
  expect(out.stderr).toMatch(/reposit/i);
  expect(fs.existsSync(inside)).toBe(false);
});

test("/safety mostra o número de segurança (igual ao calculado dos dois lados) e /trust passa a marcar [verificado]", async () => {
  const { out, room } = await roomWithBob();
  await bobSays(room, "antes", "b1");
  await waitUntil(() => out.stdout.includes("[não verificado]: antes"), "mensagem não verificada");
  const aliceKeys = (await bob.call("get", `/keys/${alice.id}`)).body;
  const expected = await e2ee.safetyNumber({ userId: alice.id, ...aliceKeys }, { userId: bob.id, ...bob.pub });
  child.stdin.write(`/safety ${bob.id}\n`);
  await waitUntil(() => out.stdout.includes(expected), "número de segurança");
  child.stdin.write(`/trust ${bob.id}\n`);
  await waitUntil(() => /marcado como verificado/.test(out.stdout), "confirmação");
  await bobSays(room, "depois", "b2");
  await waitUntil(() => out.stdout.includes(`usuário ${bob.id} [verificado]: depois`), "mensagem verificada");
  child.stdin.end();
  expect(await out.exited).toBe(0);
}, 30000);

test("/trust sem /safety antes é recusado (o usuário precisa ver o número)", async () => {
  const { out } = await roomWithBob();
  child.stdin.write(`/trust ${bob.id}\n`);
  await waitUntil(() => /use \/safety/.test(out.stdout), "recusa");
  child.stdin.end();
  await out.exited;
}, 30000);

test("CHAVE ALTERADA: Bob troca as chaves → o cliente NÃO entrega a chave da sala nem aceita mensagens dele até /safety + /trust", async () => {
  const { out, room } = await roomWithBob();
  await bobSays(room, "primeira", "b1");
  await waitUntil(() => out.stdout.includes("[não verificado]: primeira"), "primeira mensagem");

  bob.identity = await e2ee.generateIdentity();
  bob.pub = await e2ee.exportPublicKeys(bob.identity);
  bob.keyEpoch = (await bob.call("post", "/keys/reset").send(bob.pub)).body.keyEpoch;
  await waitUntil(() => /CHAVE ALTERADA de usuário/.test(out.stdout), "aviso de chave alterada");
  expect((await pool.query("SELECT 1 FROM room_key_wraps WHERE recipient_id = $1", [bob.id])).rowCount).toBe(0);

  await bobSays(room, "com a chave nova", "b2"); // Bob ainda tem a chave da sala na memória
  await waitUntil(() => out.stdout.includes("mensagem recusada"), "recusa da mensagem");
  expect(out.stdout).not.toContain("com a chave nova");

  child.stdin.write(`/safety ${bob.id}\n`);
  await waitUntil(() => /número de segurança com usuário/.test(out.stdout), "número");
  child.stdin.write(`/trust ${bob.id}\n`);
  await waitUntil(() => (out.stdout.match(/chave da sala entregue a usuário/g) ?? []).length >= 2, "nova entrega");
  room.roomKey = await fetchRoomKey(bob, room.roomId);
  await bobSays(room, "confiável de novo", "b3");
  await waitUntil(() => out.stdout.includes(`usuário ${bob.id} [verificado]: confiável de novo`), "mensagem aceita");
  child.stdin.end();
  expect(await out.exited).toBe(0);
}, 40000);

test("mensagem acima do limite é recusada no próprio cliente (nada é enviado)", async () => {
  const { out } = await roomWithBob();
  child.stdin.write(`${"é".repeat(3000)}\n`); // 6000 bytes > 5886
  await waitUntil(() => /longa demais/.test(out.stdout), "recusa local");
  child.stdin.end();
  expect(await out.exited).toBe(1);
  expect((await pool.query("SELECT count(*)::int AS n FROM messages")).rows[0].n).toBe(0);
}, 30000);

test("/keys e /members", async () => {
  const { out } = await roomWithBob();
  const aliceKeys = (await bob.call("get", `/keys/${alice.id}`)).body;
  const bobFp = await e2ee.fingerprint(bob.pub);
  child.stdin.write("/keys\n/members\n");
  await waitUntil(() => out.stdout.includes(aliceKeys.fingerprint), "fingerprint própria");
  await waitUntil(() => out.stdout.includes(`${bob.id} bob ${bobFp.slice(0, 16)}`), "membros");
  child.stdin.end();
  await out.exited;
}, 30000);
