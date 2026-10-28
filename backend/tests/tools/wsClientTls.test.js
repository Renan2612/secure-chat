// Cliente de referência com TLS (Etapa 4a): https:// + wss://, confiando
// numa CA própria (--ca ou NODE_EXTRA_CA_CERTS). A verificação do
// certificado nunca é desligada, e o cliente não rebaixa wss → ws (o cookie
// de sessão iria em claro).
//
// Uma CA e um certificado descartáveis são gerados com openssl num
// diretório temporário (nada vai para o repositório), e um terminador TLS
// na frente do servidor de teste faz o papel do Caddy.
const fs = require("fs");
const os = require("os");
const path = require("path");
const net = require("net");
const tls = require("tls");
const { execFileSync, spawn } = require("child_process");
const { pool, resetDb, createRoomInDb, PASSWORD } = require("../helpers");
const { startServer, loginUser, ORIGIN } = require("../ws/helpers");

const CLIENT = path.join(__dirname, "..", "..", "tools", "ws-client.js");

let dir;
let srv;
let terminator;
let httpsUrl;
let alice;
let room;

const openssl = (...args) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "ws-client-tls-"));
  const ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"];
  openssl("req", "-x509", ...ec, "-keyout", "ca.key", "-out", "ca.crt", "-days", "1", "-subj", "/CN=CA de teste",
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign");
  openssl("req", ...ec, "-keyout", "srv.key", "-out", "srv.csr", "-subj", "/CN=localhost");
  fs.writeFileSync(path.join(dir, "ext.cnf"), "subjectAltName=DNS:localhost,IP:127.0.0.1\n");
  openssl("x509", "-req", "-in", "srv.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
    "-out", "srv.crt", "-days", "1", "-extfile", "ext.cnf");
  // Certificado autoassinado, de fora da CA de teste: o "impostor".
  openssl("req", "-x509", ...ec, "-keyout", "rogue.key", "-out", "rogue.crt", "-days", "1", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1");
});

// Terminador TLS na frente do backend de teste, com o certificado dado.
const startTerminator = async (keyFile, certFile) => {
  const backendPort = Number(new URL(srv.wsUrl).port);
  const server = tls.createServer(
    { key: fs.readFileSync(path.join(dir, keyFile)), cert: fs.readFileSync(path.join(dir, certFile)) },
    (client) => {
      const upstream = net.connect(backendPort, "127.0.0.1");
      client.pipe(upstream).pipe(client);
      client.on("error", () => upstream.destroy());
      upstream.on("error", () => client.destroy());
    }
  );
  server.on("tlsClientError", () => {});
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return server;
};
afterAll(async () => {
  fs.rmSync(dir, { recursive: true, force: true });
  await pool.end();
});

beforeEach(async () => {
  await resetDb();
  srv = await startServer();
  alice = await loginUser(srv, "alice");
  room = await createRoomInDb("Sala", [alice.id]);
  terminator = await startTerminator("srv.key", "srv.crt");
  httpsUrl = `https://localhost:${terminator.address().port}`;
});
afterEach(async () => {
  await new Promise((r) => terminator.close(r));
  await srv.stop();
});

const run = (args, env = {}) => {
  const child = spawn(process.execPath, [CLIENT, "--email", alice.email, "--room", String(room), "--origin", ORIGIN, ...args], {
    env: { ...process.env, NODE_EXTRA_CA_CERTS: "", CHAT_PASSWORD: PASSWORD, ...env },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const out = { child, stdout: "", stderr: "" };
  child.stdout.on("data", (d) => {
    out.stdout += d;
  });
  child.stderr.on("data", (d) => {
    out.stderr += d;
  });
  out.exited = new Promise((r) => child.on("exit", r));
  return out;
};

const waitUntil = async (check, label, timeoutMs = 5000) => {
  const start = Date.now();
  while (!check()) {
    if (Date.now() - start > timeoutMs) throw new Error(`timeout esperando ${label}`);
    await new Promise((r) => setTimeout(r, 20));
  }
};

const sessions = async () => (await pool.query("SELECT COUNT(*)::int AS n FROM user_sessions")).rows[0].n;

const sendOneMessage = async (out) => {
  await waitUntil(() => /inscrito na sala/.test(out.stdout), "inscrição");
  out.child.stdin.write("por wss\n");
  await waitUntil(() => /enviada/.test(out.stdout), "confirmação");
  out.child.stdin.end();
  expect(await out.exited).toBe(0);
  expect((await pool.query("SELECT message FROM messages")).rows).toEqual([{ message: "por wss" }]);
};

test("https + wss com --ca: login, inscrição e envio funcionam", async () => {
  const out = run(["--server", httpsUrl, "--ca", path.join(dir, "ca.crt")]);
  await sendOneMessage(out);
});

test("https + wss com NODE_EXTRA_CA_CERTS: também funciona", async () => {
  const out = run(["--server", httpsUrl], { NODE_EXTRA_CA_CERTS: path.join(dir, "ca.crt") });
  await sendOneMessage(out);
});

test("--ws explícito com wss:// é aceito", async () => {
  const out = run(["--server", httpsUrl, "--ws", `${httpsUrl.replace("https", "wss")}/ws`, "--ca", path.join(dir, "ca.crt")]);
  await sendOneMessage(out);
});

test("sem confiar na CA: recusa o certificado, sai com 1 e nem chega a fazer login", async () => {
  const before = await sessions();
  const out = run(["--server", httpsUrl]);
  expect(await out.exited).toBe(1);
  expect(out.stderr).toMatch(/certificate|certificado/i);
  expect(out.stderr).toMatch(/--ca/); // dica de como confiar na CA local
  expect(out.stderr).not.toMatch(/\n\s+at /);
  expect(await sessions()).toBe(before);
});

test("o WebSocket também verifica o certificado: wss:// com certificado impostor é recusado", async () => {
  const rogue = await startTerminator("rogue.key", "rogue.crt");
  const before = await sessions();
  const out = run([
    "--server", httpsUrl,
    "--ws", `wss://localhost:${rogue.address().port}/ws`,
    "--ca", path.join(dir, "ca.crt"),
  ]);
  expect(await out.exited).toBe(1);
  expect(out.stderr).toMatch(/certificate|certificado/i);
  expect((await pool.query("SELECT 1 FROM messages")).rowCount).toBe(0);
  expect(await sessions()).toBe(before); // o login aconteceu, mas houve logout
  await new Promise((r) => rogue.close(r));
});

test("NODE_TLS_REJECT_UNAUTHORIZED=0 no ambiente → o cliente se recusa a rodar", async () => {
  const out = run(["--server", httpsUrl, "--ca", path.join(dir, "ca.crt")], { NODE_TLS_REJECT_UNAUTHORIZED: "0" });
  expect(await out.exited).toBe(1);
  expect(out.stderr).toMatch(/NODE_TLS_REJECT_UNAUTHORIZED/);
});

test("NODE_EXTRA_CA_CERTS apontando para arquivo inexistente, com --ca → erro claro", async () => {
  const out = run(["--server", httpsUrl, "--ca", path.join(dir, "ca.crt")], { NODE_EXTRA_CA_CERTS: path.join(dir, "nada.crt") });
  expect(await out.exited).toBe(1);
  expect(out.stderr).toMatch(/erro: não foi possível ler NODE_EXTRA_CA_CERTS/);
});

test("não existe opção para desligar a verificação (--insecure é argumento inválido)", async () => {
  const out = run(["--server", httpsUrl, "--insecure", "1"]);
  expect(await out.exited).toBe(1);
  expect(out.stderr).toMatch(/argumento inválido: --insecure/);
});

test("https com --ws ws:// é recusado antes do login (o cookie iria em claro)", async () => {
  const before = await sessions();
  const out = run(["--server", httpsUrl, "--ws", `ws://localhost:${new URL(srv.wsUrl).port}/ws`, "--ca", path.join(dir, "ca.crt")]);
  expect(await out.exited).toBe(1);
  expect(out.stderr).toMatch(/wss:\/\//);
  expect(await sessions()).toBe(before);
});

test.each([
  ["--server com esquema inválido", ["--server", "ftp://localhost"]],
  ["--ws com esquema inválido", ["--server", "https://localhost", "--ws", "https://localhost/ws"]],
])("%s → erro claro", async (_label, args) => {
  const out = run(args);
  expect(await out.exited).toBe(1);
  expect(out.stderr).toMatch(/^erro: /);
});

test("--ca com arquivo inexistente → erro claro", async () => {
  const out = run(["--server", httpsUrl, "--ca", path.join(dir, "nao-existe.crt")]);
  expect(await out.exited).toBe(1);
  expect(out.stderr).toMatch(/erro: não foi possível ler --ca/);
});

test("o WebSocket deriva do --server: https://host/api → wss://host/ws (prefixo do proxy)", () => {
  const { wsUrlFor } = require("../../tools/ws-client");
  expect(wsUrlFor("https://localhost/api")).toBe("wss://localhost/ws");
  expect(wsUrlFor("http://127.0.0.1:8000")).toBe("ws://127.0.0.1:8000/ws");
});
