// Etapa 5 (A2): CSRF. Toda requisição que muda estado precisa do Origin da
// própria origem (CLIENT_URL) e, se tiver corpo, Content-Type JSON. Ataques:
// formulário de outro site, fetch sem Origin, text/plain "simples" (sem
// preflight), Origin "null" (iframe com sandbox, file://).
const supertest = require("supertest");
const { app, pool, resetDb, createUser, PASSWORD } = require("./helpers");

const ORIGIN = process.env.CLIENT_URL;
let alice;

beforeEach(async () => {
  await resetDb();
  alice = await createUser("alice");
});
afterAll(() => pool.end());

describe("Origin", () => {
  test.each([
    ["sem Origin", undefined],
    ["Origin de outro site", "https://evil.example"],
    ["Origin com outra porta", "http://localhost:3001"],
    ["Origin com outro esquema", "https://localhost:3000"],
    ["Origin null (iframe com sandbox)", "null"],
    ["Origin com caminho", `${ORIGIN}/`],
  ])("ATAQUE: %s → 403 e nada muda", async (_label, origin) => {
    const req = alice.agent.post("/createRoom").send({});
    if (origin === undefined) req.unset("Origin");
    else req.set("Origin", origin);
    const res = await req;
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ message: "Origem não permitida" });
    expect((await pool.query("SELECT COUNT(*)::int AS n FROM rooms")).rows[0].n).toBe(0);
  });

  test("ATAQUE: login CSRF (outro site loga a vítima numa conta do atacante) → 403", async () => {
    const res = await supertest(app).post("/login").set("Origin", "https://evil.example").send({ email: alice.email, password: PASSWORD });
    expect(res.status).toBe(403);
    expect(res.headers["set-cookie"]).toBeUndefined();
  });

  test("ATAQUE: logout de outro site (sem corpo) → 403 e a sessão continua", async () => {
    expect((await alice.agent.post("/logout").set("Origin", "https://evil.example")).status).toBe(403);
    expect((await alice.agent.get("/rooms")).status).toBe(200);
  });

  test.each(["put", "delete"])("ATAQUE: %s sem Origin → 403", async (method) => {
    const res = await alice.agent[method]("/rooms/1/retention").unset("Origin").send({ retentionSeconds: 60 });
    expect(res.status).toBe(403);
  });

  test("da própria origem: passa", async () => {
    expect((await alice.agent.post("/createRoom").send({})).status).toBe(201);
    expect((await alice.agent.post("/logout")).status).toBe(204);
  });

  test("GET não exige Origin (não muda estado)", async () => {
    expect((await alice.agent.get("/rooms").unset("Origin")).status).toBe(200);
  });
});

describe("Content-Type", () => {
  test.each([
    ["text/plain (requisição 'simples', sem preflight)", "text/plain", '{"name":"x"}'],
    ["formulário HTML", "application/x-www-form-urlencoded", "name=x"],
    ["multipart", "multipart/form-data; boundary=x", "--x--"],
  ])("ATAQUE: %s → 415", async (_label, type, body) => {
    const res = await alice.agent.post("/createRoom").set("Content-Type", type).send(body);
    expect(res.status).toBe(415);
    expect((await pool.query("SELECT COUNT(*)::int AS n FROM rooms")).rows[0].n).toBe(0);
  });

  test("JSON com charset passa", async () => {
    const res = await alice.agent.post("/createRoom").set("Content-Type", "application/json; charset=utf-8").send("{}");
    expect(res.status).toBe(201);
  });
});
