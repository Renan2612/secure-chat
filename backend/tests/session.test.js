// Sessão armazenada no servidor (item H): revogação real no logout,
// proteção contra session fixation e atributos do cookie.
const request = require("supertest");
const { app, pool, resetDb, createUser, failQueriesMatching, PASSWORD } = require("./helpers");
const { createApp } = require("../app");

beforeEach(resetDb);
afterEach(() => jest.restoreAllMocks());
afterAll(() => pool.end());

const sessionCookie = (res) =>
  (res.headers["set-cookie"] || []).find((c) => c.startsWith("sid="));

const countSessions = async () =>
  (await pool.query("SELECT count(*)::int AS n FROM user_sessions")).rows[0].n;

test("após logout, o cookie antigo não funciona mais (sessão destruída no servidor)", async () => {
  const { agent, loginResponse } = await createUser("alice");
  const stolenCookie = sessionCookie(loginResponse).split(";")[0];

  // Antes do logout, o cookie copiado funciona.
  expect((await request(app).get("/rooms").set("Cookie", stolenCookie)).status).toBe(200);

  const logout = await agent.post("/logout");
  expect(logout.status).toBe(204);

  // Atacante reaproveita o cookie copiado: o servidor não reconhece mais.
  const replay = await request(app).get("/rooms").set("Cookie", stolenCookie);
  expect(replay.status).toBe(401);
});

test("logout limpa o cookie no navegador", async () => {
  const { agent } = await createUser("alice");
  const logout = await agent.post("/logout");
  expect(sessionCookie(logout)).toMatch(/Expires=Thu, 01 Jan 1970/);
});

test("logout remove a sessão do banco", async () => {
  const { agent } = await createUser("alice");
  expect(await countSessions()).toBe(1);
  await agent.post("/logout");
  expect(await countSessions()).toBe(0);
});

test("login gera um ID de sessão novo (sem session fixation)", async () => {
  const { agent, email, loginResponse } = await createUser("alice");
  const first = sessionCookie(loginResponse);
  const second = sessionCookie(
    await agent.post("/login").send({ email, password: PASSWORD })
  );
  expect(second).toBeDefined();
  expect(second.split(";")[0]).not.toBe(first.split(";")[0]);
  // A sessão anterior foi descartada no servidor, não apenas substituída no cliente.
  expect((await request(app).get("/rooms").set("Cookie", first.split(";")[0])).status).toBe(401);
});

test("o cookie de sessão guarda só um ID opaco, não dados do usuário", async () => {
  const { loginResponse, id } = await createUser("alice");
  const value = decodeURIComponent(sessionCookie(loginResponse).split(";")[0].slice("sid=".length));
  // Formato do express-session: "s:<id aleatório>.<assinatura HMAC>".
  const match = value.match(/^s:([^.]+)\.[^.]+$/);
  expect(match).not.toBeNull();
  // Os dados ficam no servidor, indexados por esse ID.
  const { rows } = await pool.query("SELECT sess FROM user_sessions WHERE sid = $1", [match[1]]);
  expect(rows).toHaveLength(1);
  expect(rows[0].sess.userId).toBe(id);
});

test("cookie tem nome genérico, HttpOnly, SameSite=Lax e Max-Age", async () => {
  const { loginResponse } = await createUser("alice");
  const cookie = sessionCookie(loginResponse);
  expect(cookie).toBeDefined();
  expect(cookie).toMatch(/HttpOnly/);
  expect(cookie).toMatch(/SameSite=Lax/);
  const expires = Date.parse(cookie.match(/Expires=([^;]+)/)[1]);
  const eightHours = 8 * 60 * 60 * 1000;
  expect(Math.abs(expires - (Date.now() + eightHours))).toBeLessThan(60 * 1000);
  expect(cookie).not.toMatch(/Secure/); // fora de produção, sem HTTPS
});

test("requisição anônima não cria sessão nem cookie", async () => {
  const res = await request(app).get("/health");
  expect(sessionCookie(res)).toBeUndefined();
  expect(await countSessions()).toBe(0);
});

describe("configuração de produção", () => {
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
  });

  test("cookie sai com Secure atrás de proxy HTTPS confiável", async () => {
    process.env.NODE_ENV = "production";
    process.env.TRUST_PROXY = "1";
    const prodApp = createApp({ authRateLimitMax: 10000 });
    await request(prodApp)
      .post("/register")
      .send({ email: "prod@example.com", password: PASSWORD, name: "Prod" });
    const res = await request(prodApp)
      .post("/login")
      .set("X-Forwarded-Proto", "https")
      .send({ email: "prod@example.com", password: PASSWORD });
    expect(sessionCookie(res)).toMatch(/Secure/);
  });

  test("rotação: cookie assinado com o segredo anterior continua válido", async () => {
    const { loginResponse } = await createUser("alice");
    const cookie = sessionCookie(loginResponse).split(";")[0];
    process.env.SESSION_SECRET_PREVIOUS = process.env.SESSION_SECRET;
    process.env.SESSION_SECRET = "novo-segredo-de-sessao-apos-rotacao-0123456789";
    const rotated = createApp({ authRateLimitMax: 10000 });
    expect((await request(rotated).get("/rooms").set("Cookie", cookie)).status).toBe(200);
  });

  test("sem o segredo anterior configurado, o cookie antigo deixa de valer", async () => {
    const { loginResponse } = await createUser("alice");
    const cookie = sessionCookie(loginResponse).split(";")[0];
    process.env.SESSION_SECRET = "novo-segredo-de-sessao-apos-rotacao-0123456789";
    const rotated = createApp({ authRateLimitMax: 10000 });
    expect((await request(rotated).get("/rooms").set("Cookie", cookie)).status).toBe(401);
  });

  test("app não sobe sem SESSION_SECRET", () => {
    delete process.env.SESSION_SECRET;
    expect(() => createApp()).toThrow(/SESSION_SECRET/);
  });

  test("app não sobe com SESSION_SECRET curto", () => {
    process.env.SESSION_SECRET = "curto";
    expect(() => createApp()).toThrow(/SESSION_SECRET/);
  });
});

test("falha ao gravar a sessão no login: 500 sem deixar o usuário logado", async () => {
  const { email } = await createUser("alice");
  await pool.query("DELETE FROM user_sessions");
  jest.spyOn(console, "error").mockImplementation(() => {});
  // Primeira gravação de sessão falha (ex.: timeout do pool); as seguintes funcionariam.
  const injected = failQueriesMatching(/INSERT INTO "?[a-z_."]*user_sessions/i, new Error("timeout"));

  const res = await request(app).post("/login").send({ email, password: PASSWORD });

  expect(injected.count).toBe(1);
  expect(res.status).toBe(500);
  expect(sessionCookie(res)).toBeUndefined();
  // Nenhuma sessão autenticada ficou gravada por uma segunda tentativa de save.
  await new Promise((r) => setImmediate(r));
  expect(await countSessions()).toBe(0);
});
