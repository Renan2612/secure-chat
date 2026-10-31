// Etapa 5 (B-D3): GET /me — quem está logado (id e nome), para o frontend
// retomar a sessão ao recarregar a página. Só a própria conta: sem e-mail,
// sem hash, sem nada de outro usuário.
const request = require("./request");
const { app, pool, resetDb, createUser } = require("./helpers");

beforeEach(resetDb);
afterAll(() => pool.end());

test("logado: devolve só id e nome da própria conta", async () => {
  const alice = await createUser("alice");
  await createUser("bob");
  const res = await alice.agent.get("/me");
  expect(res.status).toBe(200);
  expect(res.body).toEqual({ id: alice.id, name: "alice" });
});

test("sem sessão: 401", async () => {
  expect((await request(app).get("/me")).status).toBe(401);
});

test("depois do logout: 401", async () => {
  const alice = await createUser("alice");
  expect((await alice.agent.post("/logout")).status).toBe(204);
  expect((await alice.agent.get("/me")).status).toBe(401);
});

test("conta apagada com a sessão ainda viva: 401 (não 500)", async () => {
  const alice = await createUser("alice");
  await pool.query("DELETE FROM users WHERE id = $1", [alice.id]);
  expect((await alice.agent.get("/me")).status).toBe(401);
});
