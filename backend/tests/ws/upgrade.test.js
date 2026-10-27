// Ataque (item A): abrir o canal em tempo real sem sessão válida, a partir
// de outro site (Cross-Site WebSocket Hijacking) ou abrindo conexões demais.
const { pool, resetDb } = require("../helpers");
const { startServer, loginUser, openSocket } = require("./helpers");

let srv;

beforeEach(resetDb);
afterEach(async () => {
  if (srv) await srv.stop();
  srv = null;
});
afterAll(() => pool.end());

describe("upgrade sem sessão válida é recusado com 401, sem abrir o socket", () => {
  test("sem cookie", async () => {
    srv = await startServer();
    const res = await openSocket(srv);
    expect(res.status).toBe(401);
    expect(res.ws).toBeUndefined();
  });

  test("com cookie forjado", async () => {
    srv = await startServer();
    const res = await openSocket(srv, { cookie: "sid=s%3Aforjado.assinaturafalsa" });
    expect(res.status).toBe(401);
  });

  test("com cookie de sessão destruída (após logout)", async () => {
    srv = await startServer();
    const { cookie } = await loginUser(srv, "alice");
    await srv.http.post("/logout").set("Cookie", cookie);
    const res = await openSocket(srv, { cookie });
    expect(res.status).toBe(401);
  });

  test("a resposta de recusa não traz detalhes internos", async () => {
    srv = await startServer();
    const res = await openSocket(srv);
    expect(JSON.parse(res.body)).toEqual({ message: "Não autenticado" });
  });
});

describe("Origin é validado contra CLIENT_URL (Cross-Site WebSocket Hijacking)", () => {
  test("Origin de outro site → 403, mesmo com cookie válido", async () => {
    srv = await startServer();
    const { cookie } = await loginUser(srv, "alice");
    const res = await openSocket(srv, { cookie, origin: "https://site-malicioso.example" });
    expect(res.status).toBe(403);
  });

  test("sem Origin → 403", async () => {
    srv = await startServer();
    const { cookie } = await loginUser(srv, "alice");
    const res = await openSocket(srv, { cookie, origin: null });
    expect(res.status).toBe(403);
  });

  test("Origin parecido (sufixo/porta diferente) → 403", async () => {
    srv = await startServer();
    const { cookie } = await loginUser(srv, "alice");
    for (const origin of ["http://localhost:3000.evil.example", "http://localhost:3001", "https://localhost:3000"]) {
      expect((await openSocket(srv, { cookie, origin })).status).toBe(403);
    }
  });
});

test("cookie válido + Origin correto → conexão aberta", async () => {
  srv = await startServer();
  const { cookie } = await loginUser(srv, "alice");
  const { ws } = await openSocket(srv, { cookie });
  expect(ws).toBeDefined();
  ws.close();
});

test("upgrade em outro caminho → 404", async () => {
  srv = await startServer();
  const { cookie } = await loginUser(srv, "alice");
  const res = await openSocket(srv, { cookie, path: "/socket.io/" });
  expect(res.status).toBe(404);
});

describe("limites de conexões simultâneas", () => {
  test("por usuário: a conexão além do limite é recusada com 429", async () => {
    srv = await startServer({ maxConnectionsPerUser: 2 });
    const alice = await loginUser(srv, "alice");
    const bob = await loginUser(srv, "bob");
    const a1 = await openSocket(srv, { cookie: alice.cookie });
    const a2 = await openSocket(srv, { cookie: alice.cookie });
    expect((await openSocket(srv, { cookie: alice.cookie })).status).toBe(429);
    // Outro usuário não é afetado.
    const b1 = await openSocket(srv, { cookie: bob.cookie });
    expect(b1.ws).toBeDefined();
    // Fechar uma conexão libera a vaga.
    a1.ws.close();
    await new Promise((r) => a1.ws.once("close", r));
    await new Promise((r) => setTimeout(r, 50));
    const a3 = await openSocket(srv, { cookie: alice.cookie });
    expect(a3.ws).toBeDefined();
    [a2, b1, a3].forEach(({ ws }) => ws.close());
  });

  test("total: além do limite global, recusa com 503", async () => {
    srv = await startServer({ maxConnections: 1 });
    const alice = await loginUser(srv, "alice");
    const bob = await loginUser(srv, "bob");
    const a1 = await openSocket(srv, { cookie: alice.cookie });
    expect((await openSocket(srv, { cookie: bob.cookie })).status).toBe(503);
    a1.ws.close();
  });

  test("padrões: 5 por usuário", () => {
    const { DEFAULT_LIMITS } = require("../../realtime/protocol");
    expect(DEFAULT_LIMITS.maxConnectionsPerUser).toBe(5);
  });
});
