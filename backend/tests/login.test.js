// Ataque: enumeração de contas pelo login (mensagem, status ou tempo de
// resposta diferentes para "e-mail não existe" e "senha errada").
// Custo real: o teste de tempo equalizado precisa do bcrypt com custo de
// produção (definido antes de carregar os módulos que o leem).
process.env.BCRYPT_COST = "12";

const request = require("./request");
const { app, pool, resetDb, createUser, failQueriesMatching, PASSWORD } = require("./helpers");
const { createApp } = require("../app");

beforeEach(resetDb);
afterEach(() => jest.restoreAllMocks());
afterAll(() => pool.end());

const comparable = (res) => ({
  status: res.status,
  body: res.body,
  contentLength: res.headers["content-length"],
  setCookie: res.headers["set-cookie"],
});

test("e-mail inexistente e senha errada recebem resposta idêntica (401, Credenciais inválidas)", async () => {
  const { email } = await createUser("alice");

  const unknownUser = await request(app)
    .post("/login")
    .send({ email: "nao-existe@example.com", password: PASSWORD });
  const wrongPassword = await request(app)
    .post("/login")
    .send({ email, password: "senha-errada-123" });

  expect(comparable(unknownUser)).toEqual(comparable(wrongPassword));
  expect(unknownUser.status).toBe(401);
  expect(unknownUser.body).toEqual({ message: "Credenciais inválidas" });
  expect(unknownUser.headers["set-cookie"]).toBeUndefined();
});

test("e-mail inexistente também paga o custo do bcrypt (tempo equalizado)", async () => {
  const { email } = await createUser("alice");
  const elapsed = async (body) => {
    const start = process.hrtime.bigint();
    await request(app).post("/login").send(body);
    return Number(process.hrtime.bigint() - start) / 1e6;
  };
  // Mediana de algumas medições, para reduzir ruído.
  const median = async (body) => {
    const runs = [];
    for (let i = 0; i < 5; i += 1) runs.push(await elapsed(body));
    return runs.sort((a, b) => a - b)[2];
  };

  const unknownMs = await median({ email: "nao-existe@example.com", password: PASSWORD });
  const wrongMs = await median({ email, password: "senha-errada-123" });

  // Sem o hash fictício, a resposta para e-mail inexistente sai ~100x mais
  // rápida (não roda bcrypt). Com ele, as duas ficam na mesma ordem.
  expect(unknownMs).toBeGreaterThan(wrongMs * 0.5);
});

test("login correto responde 200 com id e nome, sem dados sensíveis", async () => {
  const { email, id } = await createUser("alice");
  const res = await request(app).post("/login").send({ email, password: PASSWORD });
  expect(res.status).toBe(200);
  expect(res.body).toEqual({ id, name: "alice" });
});

describe("e-mail normalizado e único", () => {
  test("cadastro guarda o e-mail em minúsculas e o login ignora caixa/espaços", async () => {
    const reg = await request(app)
      .post("/register")
      .send({ email: "  Alice@Example.COM ", password: PASSWORD, name: "Alice" });
    expect(reg.status).toBe(201);
    expect(reg.body.email).toBe("alice@example.com");

    const login = await request(app)
      .post("/login")
      .send({ email: "ALICE@example.com", password: PASSWORD });
    expect(login.status).toBe(200);
  });

  test("não dá para cadastrar o mesmo e-mail com outra caixa", async () => {
    await request(app).post("/register").send({ email: "bob@example.com", password: PASSWORD, name: "Bob" });
    const dup = await request(app)
      .post("/register")
      .send({ email: "BOB@example.com", password: PASSWORD, name: "Bob 2" });
    expect(dup.status).toBe(409);
  });

  test("o banco recusa e-mail duplicado mesmo sem passar pela API", async () => {
    await pool.query("INSERT INTO users (email, password, name) VALUES ('c@example.com', 'x', 'C')");
    await expect(
      pool.query("INSERT INTO users (email, password, name) VALUES ('c@example.com', 'y', 'C2')")
    ).rejects.toThrow(/unique/i);
  });

  test("o banco recusa e-mail fora de minúsculas", async () => {
    await expect(
      pool.query("INSERT INTO users (email, password, name) VALUES ('D@example.com', 'x', 'D')")
    ).rejects.toThrow(/check/i);
  });
});

test("rate limit por e-mail no login: tentativas contra a mesma conta são barradas mesmo variando a caixa", async () => {
  const limited = createApp({ authRateLimitMax: 10000, loginEmailRateLimitMax: 3 });
  const attempt = (email) => request(limited).post("/login").send({ email, password: "senha-errada-123" });

  for (const email of ["alvo@example.com", "ALVO@example.com", "Alvo@example.com"]) {
    expect((await attempt(email)).status).toBe(401);
  }
  expect((await attempt("alvo@example.com")).status).toBe(429);
  // Outra conta não é afetada.
  expect((await attempt("outra@example.com")).status).toBe(401);
});

test("rate limit por e-mail conta só falhas: logins legítimos não gastam a cota da conta", async () => {
  const limited = createApp({ authRateLimitMax: 10000, loginEmailRateLimitMax: 3 });
  await request(limited)
    .post("/register")
    .send({ email: "dona@example.com", password: PASSWORD, name: "Dona" });
  const login = (password) => request(limited).post("/login").send({ email: "dona@example.com", password });

  for (let i = 0; i < 5; i += 1) expect((await login(PASSWORD)).status).toBe(200);
  // Depois de vários logins corretos, uma senha errada ainda é só 401.
  expect((await login("senha-errada-123")).status).toBe(401);
});

test("senha curta no login dá 401 (regra de tamanho mínimo é só do cadastro)", async () => {
  const { email } = await createUser("alice");
  const res = await request(app).post("/login").send({ email, password: "12345" });
  expect(res.status).toBe(401);
  expect(res.body).toEqual({ message: "Credenciais inválidas" });
});

test.each(["/login", "/register"])("rate limit por IP em %s (várias contas, mesmo IP)", async (path) => {
  const limited = createApp({ authRateLimitMax: 2, loginEmailRateLimitMax: 10000 });
  const send = (i) =>
    request(limited)
      .post(path)
      .send({ email: `ip${i}@example.com`, password: PASSWORD, name: `ip${i}` });
  expect((await send(1)).status).not.toBe(429);
  expect((await send(2)).status).not.toBe(429);
  const third = await send(3);
  expect(third.status).toBe(429);
  expect(third.body).toEqual({ message: "Muitas tentativas. Tente novamente em instantes." });
});

test("rate limit por e-mail não conta erros do servidor (só senha errada)", async () => {
  const limited = createApp({ authRateLimitMax: 10000, loginEmailRateLimitMax: 2 });
  const { email } = await createUser("alice");
  jest.spyOn(console, "error").mockImplementation(() => {});
  failQueriesMatching(/FROM users/, new Error("banco fora"), 3);
  for (let i = 0; i < 3; i += 1) {
    expect((await request(limited).post("/login").send({ email, password: PASSWORD })).status).toBe(500);
  }
  jest.restoreAllMocks();
  // Banco voltou: a dona da conta não deve estar bloqueada.
  expect((await request(limited).post("/login").send({ email, password: PASSWORD })).status).toBe(200);
});
