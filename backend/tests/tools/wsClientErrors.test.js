// Cliente de referência contra servidores HTTP de mentira: respostas
// truncadas, redirecionamentos e corpos inválidos não podem deixar o
// cliente sair "com sucesso" calado, reenviar a senha nem largar sessão.
const http = require("http");
const path = require("path");
const { spawn } = require("child_process");

const { clientSetup } = require("./clientEnv");

const CLIENT = path.join(__dirname, "..", "..", "tools", "ws-client.js");

let servers = [];
afterEach(async () => {
  await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
  servers = [];
});

const fake = async (handler) => {
  const server = http.createServer(handler);
  servers.push(server);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${server.address().port}`;
};

const run = (args, env = {}) =>
  new Promise((resolve) => {
    const setup = clientSetup();
    const child = spawn(process.execPath, [CLIENT, "--email", "a@b.c", "--room", "1", ...setup.args, ...args], {
      env: { ...process.env, CHAT_PASSWORD: "senha", ...setup.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d;
    });
    child.stderr.on("data", (d) => {
      stderr += d;
    });
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });

test("resposta do login cortada no meio → sai com 1 e diz o motivo (antes: saía 0 calado)", async () => {
  const base = await fake((req, res) => {
    res.writeHead(200, { "Content-Type": "application/json", "Content-Length": "100" });
    res.write('{"id":1,');
    setTimeout(() => res.socket.destroy(), 20);
  });
  const { code, stderr } = await run(["--server", base]);
  expect(code).toBe(1);
  expect(stderr).toMatch(/resposta incompleta/);
});

test("308 no login não é seguido: a senha não é reenviada ao destino do redirecionamento", async () => {
  let targetHits = 0;
  const target = await fake((req, res) => {
    targetHits += 1;
    res.end();
  });
  const base = await fake((req, res) => {
    res.writeHead(308, { Location: `${target}/login` });
    res.end();
  });
  const { code, stderr } = await run(["--server", base]);
  expect(code).toBe(1);
  expect(stderr).toMatch(/login falhou \(308\).*https:\/\//);
  expect(targetHits).toBe(0);
});

test("http:// fora do loopback é recusado antes de mandar a senha", async () => {
  const { code, stderr } = await run(["--server", "http://example.invalid/api"]);
  expect(code).toBe(1);
  expect(stderr).toMatch(/http:\/\/ só é aceito para localhost/);
});

test("login 200 com corpo inválido → faz logout antes de sair (não larga a sessão)", async () => {
  let logouts = 0;
  const base = await fake((req, res) => {
    if (req.url === "/logout") {
      logouts += 1;
      res.writeHead(204);
      return res.end();
    }
    res.writeHead(200, { "Set-Cookie": "sid=s%3Ax.y; HttpOnly", "Content-Type": "application/json" });
    return res.end("isto não é json");
  });
  const { code, stderr } = await run(["--server", base]);
  expect(code).toBe(1);
  expect(stderr).toMatch(/resposta inválida do login/);
  expect(logouts).toBe(1);
});

test("logout com resposta cortada → avisa e mantém o código de saída de erro", async () => {
  const base = await fake((req, res) => {
    if (req.url === "/logout") {
      res.writeHead(200, { "Content-Length": "10" });
      res.write("abc");
      return setTimeout(() => res.socket.destroy(), 20);
    }
    // login ok, mas o upgrade vai falhar (não há /ws aqui) → erro + logout
    res.writeHead(200, { "Set-Cookie": "sid=s%3Ax.y; HttpOnly", "Content-Type": "application/json" });
    return res.end('{"id":1,"name":"x"}');
  });
  const { code, stderr } = await run(["--server", base]);
  expect(code).toBe(1);
  expect(stderr).toMatch(/aviso: logout falhou/);
});
