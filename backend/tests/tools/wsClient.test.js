// Cliente de referência (tools/ws-client.js): login por HTTP, /ws, HELLO,
// SUBSCRIBE e envio/recebimento — executado de verdade como processo filho.
const path = require("path");
const { spawn } = require("child_process");
const { pool, resetDb, createRoomInDb, PASSWORD } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, send, ORIGIN } = require("../ws/helpers");

const CLIENT = path.join(__dirname, "..", "..", "tools", "ws-client.js");

let srv;
let alice;
let bob;
let room;
let child;

beforeEach(async () => {
  await resetDb();
  srv = await startServer();
  alice = await loginUser(srv, "alice");
  bob = await loginUser(srv, "bob");
  room = await createRoomInDb("Sala", [alice.id, bob.id]);
});
afterEach(async () => {
  if (child && child.exitCode === null) child.kill();
  await srv.stop();
});
afterAll(() => pool.end());

const run = (email, password, extraArgs = []) => {
  const httpUrl = srv.wsUrl.replace(/^ws/, "http").replace(/\/ws$/, "");
  child = spawn(
    process.execPath,
    [CLIENT, "--server", httpUrl, "--email", email, "--room", String(room), "--origin", ORIGIN, ...extraArgs],
    { env: { ...process.env, CHAT_PASSWORD: password }, stdio: ["pipe", "pipe", "pipe"] }
  );
  const out = { stdout: "", stderr: "" };
  child.stdout.on("data", (d) => {
    out.stdout += d;
  });
  child.stderr.on("data", (d) => {
    out.stderr += d;
  });
  out.exited = new Promise((resolve) => child.on("exit", resolve));
  return out;
};

const waitUntil = async (check, label, timeoutMs = 5000) => {
  const start = Date.now();
  while (!check()) {
    if (Date.now() - start > timeoutMs) throw new Error(`timeout esperando ${label}`);
    await new Promise((r) => setTimeout(r, 20));
  }
};

test("entra na sala, envia o que for digitado e mostra o que chega", async () => {
  const out = run(alice.email, PASSWORD);
  await waitUntil(() => /inscrito na sala/.test(out.stdout), "inscrição");

  const bobConn = await connect(srv, bob.cookie);
  send(bobConn.ws, { type: "SUBSCRIBE", room });
  await nextPacket(bobConn.inbox, "SUBSCRIBED");

  child.stdin.write("olá do cliente de referência\n");
  expect(await nextPacket(bobConn.inbox, "MSG_DELIVER", 5000)).toMatchObject({
    from: alice.id,
    body: "olá do cliente de referência",
  });
  await waitUntil(() => /enviada/.test(out.stdout), "confirmação");

  send(bobConn.ws, { type: "MSG_SEND", room, cid: "b1", body: "resposta do bob" });
  await waitUntil(() => out.stdout.includes("resposta do bob"), "entrega");
  expect(out.stdout).toContain(`usuário ${bob.id}`);

  child.stdin.end();
  expect(await out.exited).toBe(0);
  bobConn.ws.close();
});

test("ao sair, faz logout: a sessão usada pelo cliente deixa de existir", async () => {
  const out = run(alice.email, PASSWORD);
  await waitUntil(() => /inscrito na sala/.test(out.stdout), "inscrição");
  const before = (await pool.query("SELECT COUNT(*)::int AS n FROM user_sessions")).rows[0].n;
  child.stdin.end();
  expect(await out.exited).toBe(0);
  const after = (await pool.query("SELECT COUNT(*)::int AS n FROM user_sessions")).rows[0].n;
  expect(after).toBe(before - 1);
});

test("credenciais inválidas: sai com código 1 e mensagem curta, sem stack", async () => {
  const out = run(alice.email, "senha-errada-123");
  expect(await out.exited).toBe(1);
  expect(out.stderr).toMatch(/login falhou \(401\)/);
  expect(out.stderr).not.toMatch(/\n\s+at /);
});

test("sem CHAT_PASSWORD e sem terminal: recusa em vez de travar", async () => {
  const out = run(alice.email, "");
  expect(await out.exited).toBe(1);
  expect(out.stderr).toMatch(/CHAT_PASSWORD/);
});

test("sala da qual não é membro: mostra NOT_MEMBER e sai com código 1", async () => {
  room = await createRoomInDb("Alheia", [bob.id]);
  const out = run(alice.email, PASSWORD);
  expect(await out.exited).toBe(1);
  expect(out.stdout).toMatch(/NOT_MEMBER/);
});

test("mensagem recusada (ERROR) não deixa o cliente pendurado no fim da entrada", async () => {
  const out = run(alice.email, PASSWORD);
  await waitUntil(() => /inscrito na sala/.test(out.stdout), "inscrição");
  child.stdin.write(`${"é".repeat(5000)}\n`); // 10000 bytes > limite do body
  await waitUntil(() => /BAD_REQUEST/.test(out.stdout), "erro");
  child.stdin.end();
  expect(await out.exited).toBe(1); // houve envio recusado
});

const sessionCount = async () => (await pool.query("SELECT COUNT(*)::int AS n FROM user_sessions")).rows[0].n;

test("upgrade recusado depois do login: sai com 1 e não deixa a sessão viva", async () => {
  const before = await sessionCount();
  const out = run(alice.email, PASSWORD, ["--origin", "https://outra-origem.example"]);
  expect(await out.exited).toBe(1);
  expect(out.stderr).toMatch(/upgrade recusado \(403\)/);
  expect(await sessionCount()).toBe(before);
});

test("logout que falha no fim é avisado (a sessão pode continuar válida)", async () => {
  const out = run(alice.email, PASSWORD);
  await waitUntil(() => /inscrito na sala/.test(out.stdout), "inscrição");
  await pool.query("DELETE FROM user_sessions"); // o logout vai receber 401
  child.stdin.end();
  await out.exited;
  expect(out.stderr).toMatch(/aviso: logout falhou/);
});

test("linhas descartadas pelo rate limit não penduram o cliente: avisa as não confirmadas e sai", async () => {
  const out = run(alice.email, PASSWORD, ["--ack-timeout-ms", "800"]);
  await waitUntil(() => /inscrito na sala/.test(out.stdout), "inscrição");
  // 25 linhas: 18 cabem no balde (HELLO e SUBSCRIBE gastaram 2), 7 são
  // descartadas sem resposta individual; abaixo de 20 violações, não há 4429.
  child.stdin.write(Array.from({ length: 25 }, (_, i) => `linha ${i}`).join("\n") + "\n");
  child.stdin.end();
  expect(await out.exited).toBe(1);
  expect(out.stdout).toMatch(/RATE_LIMITED/);
  const unconfirmed = out.stdout.match(/sem confirmação/g) ?? [];
  expect(unconfirmed.length).toBeGreaterThanOrEqual(1); // ~7 (o balde repõe 10/s)
  expect(unconfirmed.length).toBeLessThanOrEqual(7);
}, 10000);

test("se o servidor fecha a conexão (ex.: 4429) com envios pendentes, eles são listados como não confirmados", async () => {
  const out = run(alice.email, PASSWORD);
  await waitUntil(() => /inscrito na sala/.test(out.stdout), "inscrição");
  child.stdin.write(Array.from({ length: 40 }, (_, i) => `linha ${i}`).join("\n") + "\n");
  expect(await out.exited).toBe(1);
  expect(out.stdout).toMatch(/conexão encerrada \(4429/);
  expect(out.stdout).toMatch(/sem confirmação/);
}, 10000);

test("pacote do servidor que não é objeto JSON não derruba o cliente", async () => {
  const http = require("http");
  const WebSocket = require("ws");
  const fake = http.createServer((req, res) => {
    res.writeHead(200, { "Set-Cookie": "sid=falso; HttpOnly", "Content-Type": "application/json" });
    res.end(JSON.stringify({ id: 1, name: "x" }));
  });
  const wss = new WebSocket.Server({ server: fake });
  wss.on("connection", (ws) => {
    ws.send("null");
    ws.send("42");
    ws.close(1000);
  });
  await new Promise((r) => fake.listen(0, "127.0.0.1", r));
  child = spawn(
    process.execPath,
    [CLIENT, "--server", `http://127.0.0.1:${fake.address().port}`, "--email", "a@b.c", "--room", "1"],
    { env: { ...process.env, CHAT_PASSWORD: "x" }, stdio: ["pipe", "pipe", "pipe"] }
  );
  let stderr = "";
  let stdout = "";
  child.stderr.on("data", (d) => {
    stderr += d;
  });
  child.stdout.on("data", (d) => {
    stdout += d;
  });
  await new Promise((r) => child.on("exit", r));
  wss.close();
  fake.close();
  expect(stderr).not.toMatch(/TypeError/);
  expect(stdout).toMatch(/quadro inválido/);
});
