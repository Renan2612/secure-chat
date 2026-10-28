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

  // Segura as leituras de sessão dos upgrades e as solta juntas: assim as
  // checagens de limite de todos rodam intercaladas (a corrida de verdade).
  const releaseSessionsTogether = (count) => {
    const realQuery = pool.query.bind(pool);
    const waiting = [];
    let release;
    const gate = new Promise((r) => {
      release = r;
    });
    const spy = jest.spyOn(pool, "query").mockImplementation(async (text, ...rest) => {
      const sql = typeof text === "string" ? text : text?.text;
      if (!/SELECT sess FROM/.test(sql || "")) return realQuery(text, ...rest);
      const result = await realQuery(text, ...rest);
      waiting.push(result);
      if (waiting.length === count) release();
      await gate;
      return result;
    });
    return () => spy.mockRestore();
  };

  test("upgrades simultâneos não furam o limite por usuário", async () => {
    srv = await startServer({ maxConnectionsPerUser: 2 });
    const alice = await loginUser(srv, "alice");
    const restore = releaseSessionsTogether(6);
    const results = await Promise.all(Array.from({ length: 6 }, () => openSocket(srv, { cookie: alice.cookie })));
    restore();
    expect(results.filter((r) => r.ws)).toHaveLength(2);
    expect(results.filter((r) => r.status === 429)).toHaveLength(4);
    results.forEach((r) => r.ws?.close());
  });

  test("upgrades simultâneos não furam o limite total", async () => {
    srv = await startServer({ maxConnections: 3 });
    const users = [];
    for (let i = 0; i < 6; i += 1) users.push(await loginUser(srv, `u${i}`));
    const restore = releaseSessionsTogether(6);
    const results = await Promise.all(users.map((u) => openSocket(srv, { cookie: u.cookie })));
    restore();
    expect(results.filter((r) => r.ws)).toHaveLength(3);
    expect(results.filter((r) => r.status === 503)).toHaveLength(3);
    results.forEach((r) => r.ws?.close());
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

describe("falha fechada do Origin", () => {
  test("CLIENT_URL ausente → 403 até para a origem que seria a correta", async () => {
    srv = await startServer();
    const { cookie } = await loginUser(srv, "alice");
    const saved = process.env.CLIENT_URL;
    delete process.env.CLIENT_URL;
    try {
      expect((await openSocket(srv, { cookie })).status).toBe(403);
    } finally {
      process.env.CLIENT_URL = saved;
    }
  });

  test('Origin "null" (iframe sandbox, file://) → 403', async () => {
    srv = await startServer();
    const { cookie } = await loginUser(srv, "alice");
    expect((await openSocket(srv, { cookie, origin: "null" })).status).toBe(403);
  });
});

test("sessão expirada (ainda no banco) → 401 no upgrade", async () => {
  srv = await startServer();
  const { cookie } = await loginUser(srv, "alice");
  await pool.query("UPDATE user_sessions SET expire = NOW() - INTERVAL '1 minute'");
  expect((await openSocket(srv, { cookie })).status).toBe(401);
});
