// Ponta a ponta com DOIS processos do ws-client (opt-in: E2E=1, ou
// `npm run test:e2e`). Alice cria a sala; Bob entra com o convite; Alice o
// aprova (/approve) e o cliente dela entrega a chave; os dois trocam mensagens
// cifradas e cada um decifra a do outro. O banco nunca vê o texto.
const path = require("path");
const { spawn } = require("child_process");
const { pool, resetDb, PASSWORD } = require("../helpers");
const { startServer, loginUser, ORIGIN } = require("../ws/helpers");
const { clientSetup } = require("../tools/clientEnv");

const CLIENT = path.join(__dirname, "..", "..", "tools", "ws-client.js");
const maybe = process.env.E2E === "1" ? describe : describe.skip;

maybe("e2e: dois clientes de referência", () => {
  let srv;
  const children = [];

  beforeEach(async () => {
    await resetDb();
    srv = await startServer();
  });
  afterEach(async () => {
    for (const c of children) if (c.exitCode === null) c.kill();
    await srv.stop();
  });
  afterAll(() => pool.end());

  const start = (email, args) => {
    const httpUrl = srv.wsUrl.replace(/^ws/, "http").replace(/\/ws$/, "");
    const setup = clientSetup();
    const child = spawn(process.execPath, [CLIENT, "--server", httpUrl, "--email", email, "--origin", ORIGIN, ...setup.args, ...args], {
      env: { ...process.env, CHAT_PASSWORD: PASSWORD, ...setup.env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    children.push(child);
    const out = { child, stdout: "" };
    child.stdout.on("data", (d) => {
      out.stdout += d;
    });
    out.exited = new Promise((r) => child.on("exit", r));
    return out;
  };

  const waitUntil = async (check, label, timeoutMs = 10000) => {
    const startAt = Date.now();
    for (;;) {
      const value = check();
      if (value) return value;
      if (Date.now() - startAt > timeoutMs) throw new Error(`timeout esperando ${label}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  };

  test("Alice e Bob trocam mensagens cifradas; cada um decifra a do outro", async () => {
    const alice = await loginUser(srv, "alice");
    const bob = await loginUser(srv, "bob");
    const a = start(alice.email, ["--create-room", "Sala e2e"]);
    const [, id, invite] = await waitUntil(() => a.stdout.match(/sala criada: id (\d+); convite: ([0-9a-f]+)/), "sala criada");
    const b = start(bob.email, ["--room", id, "--join", invite]);
    // Quem decide quem é membro é o servidor: Alice aprova o Bob explicitamente.
    await waitUntil(() => a.stdout.includes(`/approve ${bob.id}`), "Alice vê o Bob aguardando a chave");
    a.child.stdin.write(`/approve ${bob.id}\n`);
    await waitUntil(() => /chave da sala \d+ disponível/.test(b.stdout), "Bob recebe a chave");

    const fromAlice = `ALICE-${Date.now()}`;
    const fromBob = `BOB-${Date.now()}`;
    a.child.stdin.write(`${fromAlice}\n`);
    await waitUntil(() => b.stdout.includes(`usuário ${alice.id} [não verificado]: ${fromAlice}`), "Bob decifra a mensagem da Alice");
    b.child.stdin.write(`${fromBob}\n`);
    await waitUntil(() => a.stdout.includes(`usuário ${bob.id} [não verificado]: ${fromBob}`), "Alice decifra a mensagem do Bob");

    const { rows } = await pool.query("SELECT message FROM messages");
    expect(rows).toHaveLength(2);
    for (const { message } of rows) {
      expect(message).not.toContain(fromAlice);
      expect(message).not.toContain(fromBob);
    }
    a.child.stdin.end();
    b.child.stdin.end();
    expect(await a.exited).toBe(0);
    expect(await b.exited).toBe(0);
  }, 40000);
});
