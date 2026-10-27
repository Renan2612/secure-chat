// Ataque: atacante sem conta (sem sessão) tenta usar a API diretamente.
const request = require("supertest");
const { app, pool, resetDb, PASSWORD } = require("./helpers");

beforeEach(resetDb);
afterAll(() => pool.end());

const protectedRoutes = [
  ["get", "/rooms"],
  ["post", "/logout"],
  ["get", "/messages/1"],
  ["post", "/messages"],
  ["post", "/updateLastViewed"],
  ["post", "/checkRoomExists"],
  ["post", "/createRoom"],
  ["post", "/joinRooms"],
  ["get", "/roomUsers/1"],
  // Rota inexistente também exige sessão: o 401 vem antes do 404, então
  // um atacante sem conta não consegue nem mapear quais rotas existem.
  ["get", "/rota-que-nao-existe"],
];

describe.each(protectedRoutes)("%s %s sem sessão", (method, path) => {
  test("responde 401 em JSON", async () => {
    const res = await request(app)[method](path).send({});
    expect(res.status).toBe(401);
    expect(res.headers["content-type"]).toMatch(/application\/json/);
    expect(res.body).toEqual({ message: "Não autenticado" });
  });
});

test("cookie de sessão forjado/inválido também recebe 401", async () => {
  const res = await request(app).get("/rooms").set("Cookie", "sid=s%3Aforjado.assinaturafalsa");
  expect(res.status).toBe(401);
});

describe("rotas públicas continuam acessíveis sem sessão", () => {
  test("GET /health responde 200", async () => {
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok" });
  });

  test("POST /register não exige sessão", async () => {
    const res = await request(app)
      .post("/register")
      .send({ email: "novo@example.com", password: PASSWORD, name: "Novo" });
    expect(res.status).toBe(201);
  });

  test("POST /login não exige sessão", async () => {
    const res = await request(app)
      .post("/login")
      .send({ email: "ninguem@example.com", password: PASSWORD });
    // Chega ao handler de login (401 por credenciais), não ao requireAuth.
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ message: "Credenciais inválidas" });
  });
});
