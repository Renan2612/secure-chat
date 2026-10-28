// Ataque: inundar /ws com pedidos de upgrade (cada um custa uma leitura de
// sessão no banco), inclusive sem sessão. Limite por IP REAL do cliente: atrás
// do proxy, o IP vem do X-Forwarded-For com o número exato de saltos
// (TRUST_PROXY), e o que o cliente forja à esquerda não muda o balde.
const { pool, resetDb } = require("../helpers");
const { startServer, loginUser, openSocket } = require("./helpers");
const { DEFAULT_LIMITS } = require("../../realtime/protocol");

let srv;
const savedTrust = process.env.TRUST_PROXY;

beforeEach(async () => {
  await resetDb();
  srv = null;
});
afterEach(async () => {
  if (savedTrust === undefined) delete process.env.TRUST_PROXY;
  else process.env.TRUST_PROXY = savedTrust;
  jest.restoreAllMocks();
  await srv?.stop();
});
afterAll(() => pool.end());

const attempt = (xff, cookie) =>
  openSocket(srv, { headers: { ...(xff ? { "X-Forwarded-For": xff } : {}), ...(cookie ? { Cookie: cookie } : {}) } });

test("padrões: rajada de 20 tentativas de upgrade por IP, repostas a 0,5/s", () => {
  expect(DEFAULT_LIMITS).toMatchObject({ upgradeBurst: 20, upgradeRefillPerSec: 0.5 });
});

test("excesso de tentativas do mesmo IP → 429 antes de consultar a sessão no banco", async () => {
  srv = await startServer({ upgradeBurst: 3, upgradeRefillPerSec: 0.01 });
  // Com cookie (de sessão já destruída), cada tentativa lê a sessão no banco:
  // é isso que o limite precisa evitar.
  const { cookie } = await loginUser(srv, "alice");
  await srv.http.post("/logout").set("Cookie", cookie);
  const spy = jest.spyOn(pool, "query");
  const sessionReads = () => spy.mock.calls.filter(([sql]) => /SELECT sess FROM/.test(String(sql?.text ?? sql))).length;
  for (let i = 0; i < 3; i += 1) expect((await attempt(null, cookie)).status).toBe(401);
  expect(sessionReads()).toBe(3); // controle: abaixo do limite, a sessão é lida
  const res = await attempt(null, cookie);
  expect(res.status).toBe(429);
  expect(JSON.parse(res.body)).toEqual({ message: "Tentativas de conexão demais; aguarde" });
  expect(sessionReads()).toBe(3); // a recusa não tocou no banco
});

test("usuário legítimo também conta: a 4ª tentativa do mesmo IP é recusada", async () => {
  srv = await startServer({ upgradeBurst: 3, upgradeRefillPerSec: 0.01 });
  const { cookie } = await loginUser(srv, "alice");
  const opened = [];
  for (let i = 0; i < 3; i += 1) opened.push(await attempt(null, cookie));
  expect(opened.every((r) => r.ws)).toBe(true);
  expect((await attempt(null, cookie)).status).toBe(429);
  opened.forEach((r) => r.ws.close());
});

describe("com TRUST_PROXY=1 (atrás do Caddy)", () => {
  beforeEach(() => {
    process.env.TRUST_PROXY = "1";
  });

  test("o balde é do IP real: o que o cliente forja à esquerda no X-Forwarded-For não ajuda", async () => {
    srv = await startServer({ upgradeBurst: 2, upgradeRefillPerSec: 0.01 });
    expect((await attempt("1.1.1.1, 10.0.0.5")).status).toBe(401);
    expect((await attempt("2.2.2.2, 10.0.0.5")).status).toBe(401);
    expect((await attempt("3.3.3.3, 10.0.0.5")).status).toBe(429);
  });

  // Junto com o teste "sem TRUST_PROXY" abaixo: lá, os mesmos dois IPs caem
  // no mesmo balde; aqui, em baldes separados.
  test("clientes diferentes (IP real diferente) têm baldes separados", async () => {
    srv = await startServer({ upgradeBurst: 1, upgradeRefillPerSec: 0.01 });
    expect((await attempt("10.0.0.5")).status).toBe(401);
    expect((await attempt("10.0.0.5")).status).toBe(429);
    expect((await attempt("10.0.0.6")).status).toBe(401);
  });
});

test("sem TRUST_PROXY, X-Forwarded-For é ignorado: vale o IP da conexão", async () => {
  delete process.env.TRUST_PROXY;
  srv = await startServer({ upgradeBurst: 1, upgradeRefillPerSec: 0.01 });
  expect((await attempt("10.0.0.5")).status).toBe(401);
  expect((await attempt("10.0.0.6")).status).toBe(429);
});
