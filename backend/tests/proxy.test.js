// Etapa 4a: o Express atrás do proxy reverso (Caddy). Confiar no número
// EXATO de saltos, nunca em qualquer X-Forwarded-For; o rate limit precisa
// ver o IP real do cliente, e o cookie de sessão só pode sair com Secure.
const request = require("supertest");
const { createApp } = require("../app");
const { createSession } = require("../config/session");
const { pool, resetDb, createUser, PASSWORD } = require("./helpers");

const savedEnv = { TRUST_PROXY: process.env.TRUST_PROXY, NODE_ENV: process.env.NODE_ENV };
afterEach(() => {
  jest.restoreAllMocks();
  for (const [name, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});
afterAll(() => pool.end());

describe("TRUST_PROXY aceita só um número inteiro de saltos (falha fechada)", () => {
  test.each(["true", "loopback", "0", "-1", "1.5", "abc", "1, 2"])("TRUST_PROXY=%s → recusa subir", (value) => {
    process.env.TRUST_PROXY = value;
    expect(() => createApp()).toThrow(/TRUST_PROXY/);
  });

  test("NODE_ENV=production sem TRUST_PROXY → recusa subir (o cookie Secure nunca seria emitido)", () => {
    process.env.NODE_ENV = "production";
    delete process.env.TRUST_PROXY;
    const session = { middleware: (req, res, next) => next() };
    expect(() => createApp({ session })).toThrow(/TRUST_PROXY/);
  });

  test.each(["1", "2"])("TRUST_PROXY=%s é aceito como número de saltos", (value) => {
    process.env.TRUST_PROXY = value;
    expect(createApp().get("trust proxy")).toBe(Number(value));
  });
});

// O limitador de /register conta por IP; RateLimit-Remaining mostra o balde.
// Falha alto se o cabeçalho sumir: NaN === NaN no toBe tornaria vácuas as
// comparações abaixo.
const remaining = (res) => {
  const value = Number(res.headers["ratelimit-remaining"]);
  expect(Number.isInteger(value) && value >= 0).toBe(true);
  return value;
};
const probe = (app, xff) =>
  request(app).post("/register").set("X-Forwarded-For", xff).send({}); // 400, mas conta no limite

describe("rate limit com TRUST_PROXY=1 usa o IP entregue pelo proxy", () => {
  beforeEach(() => {
    process.env.TRUST_PROXY = "1";
  });

  test("X-Forwarded-For forjado pelo cliente (à esquerda) não muda o balde", async () => {
    const app = createApp({ authRateLimitMax: 50 });
    const first = await probe(app, "1.1.1.1, 10.0.0.5");
    const second = await probe(app, "2.2.2.2, 10.0.0.5");
    const third = await probe(app, "10.0.0.5");
    expect(remaining(second)).toBe(remaining(first) - 1);
    expect(remaining(third)).toBe(remaining(first) - 2);
  });

  test("clientes diferentes (IP real diferente) têm baldes separados", async () => {
    const app = createApp({ authRateLimitMax: 50 });
    const a = await probe(app, "10.0.0.5");
    const b = await probe(app, "10.0.0.6");
    expect(remaining(b)).toBe(remaining(a));
  });
});

test("sem TRUST_PROXY, X-Forwarded-For é ignorado (todos no mesmo balde)", async () => {
  delete process.env.TRUST_PROXY;
  jest.spyOn(console, "error").mockImplementation(() => {}); // aviso do express-rate-limit
  const app = createApp({ authRateLimitMax: 50 });
  const a = await probe(app, "10.0.0.5");
  const b = await probe(app, "10.0.0.6");
  expect(remaining(b)).toBe(remaining(a) - 1);
});

describe("cookie de sessão em produção, atrás do proxy TLS", () => {
  let session;
  beforeEach(async () => {
    await resetDb();
  });
  afterEach(async () => {
    await session?.store.close();
    session = null;
  });

  const prodApp = () => {
    process.env.NODE_ENV = "production";
    process.env.TRUST_PROXY = "1";
    session = createSession();
    return createApp({ session, authRateLimitMax: 1000, loginEmailRateLimitMax: 1000 });
  };

  test("login via HTTPS (X-Forwarded-Proto do proxy) → Set-Cookie com Secure, HttpOnly e SameSite", async () => {
    const { email } = await createUser("alice");
    const app = prodApp();
    const res = await request(app)
      .post("/login")
      .set("X-Forwarded-Proto", "https")
      .set("X-Forwarded-For", "10.0.0.5")
      .send({ email, password: PASSWORD });
    expect(res.status).toBe(200);
    const cookie = res.headers["set-cookie"].find((c) => c.startsWith("sid="));
    expect(cookie).toMatch(/; Secure/);
    expect(cookie).toMatch(/; HttpOnly/);
    expect(cookie).toMatch(/; SameSite=Lax/);
  });

  test("login que chegou ao proxy por HTTP não recebe cookie de sessão", async () => {
    const { email } = await createUser("alice");
    const app = prodApp();
    const res = await request(app)
      .post("/login")
      .set("X-Forwarded-Proto", "http")
      .set("X-Forwarded-For", "10.0.0.5")
      .send({ email, password: PASSWORD });
    expect(res.headers["set-cookie"] ?? []).not.toEqual(expect.arrayContaining([expect.stringMatching(/^sid=/)]));
  });
});

test("o backend não emite HSTS: quem emite é o proxy TLS (evita cabeçalho duplicado)", async () => {
  const res = await request(createApp()).get("/health");
  expect(res.headers["strict-transport-security"]).toBeUndefined();
  // Os demais cabeçalhos de conteúdo continuam vindo do helmet.
  expect(res.headers["x-content-type-options"]).toBe("nosniff");
});
