// Validação de entrada: tudo que não segue o formato esperado é recusado
// com 400 e uma mensagem genérica, antes de chegar ao banco.
const request = require("supertest");
const { app, pool, resetDb, createUser, createRoomInDb } = require("./helpers");

const INVALID = { message: "Requisição inválida" };
const INT_MAX = 2147483647; // limite do INTEGER do Postgres

let alice;
let roomId;

beforeEach(async () => {
  await resetDb();
  alice = await createUser("alice");
  roomId = await createRoomInDb("Sala", [alice.id]);
});

afterAll(() => pool.end());

const validUser = { email: "valido@example.com", password: "senha-forte-de-teste", name: "Válido" };

describe("POST /register", () => {
  test.each([
    ["e-mail inválido", { ...validUser, email: "nao-e-email" }],
    ["e-mail como objeto", { ...validUser, email: { $ne: "" } }],
    ["e-mail longo demais", { ...validUser, email: `${"a".repeat(250)}@example.com` }],
    ["senha com 9 caracteres", { ...validUser, password: "123456789" }],
    ["senha com mais de 72 bytes (multibyte)", { ...validUser, password: "é".repeat(37) }],
    ["senha não-string", { ...validUser, password: 1234567890123 }],
    ["nome vazio", { ...validUser, name: "   " }],
    ["nome longo demais", { ...validUser, name: "n".repeat(101) }],
    ["campos ausentes", {}],
  ])("%s → 400", async (_label, body) => {
    const res = await request(app).post("/register").send(body);
    expect(res.status).toBe(400);
    expect(res.body).toEqual(INVALID);
  });

  test("senha com exatamente 72 bytes é aceita", async () => {
    const res = await request(app)
      .post("/register")
      .send({ ...validUser, password: "a".repeat(72) });
    expect(res.status).toBe(201);
  });
});

describe("POST /login", () => {
  test.each([
    ["e-mail inválido", { email: "x", password: "senha-forte-de-teste" }],
    ["senha acima de 72 bytes", { email: "a@example.com", password: "a".repeat(73) }],
    ["senha vazia", { email: "a@example.com", password: "" }],
    ["tipos errados", { email: ["a@example.com"], password: { x: 1 } }],
  ])("%s → 400", async (_label, body) => {
    const res = await request(app).post("/login").send(body);
    expect(res.status).toBe(400);
    expect(res.body).toEqual(INVALID);
  });
});

describe("rotas de sala", () => {
  test.each([
    ["createRoom sem nome", "/createRoom", { name: "" }],
    ["createRoom com nome longo", "/createRoom", { name: "s".repeat(101) }],
    ["createRoom com nome não-string", "/createRoom", { name: 42 }],
    ["checkRoomExists com nome longo", "/checkRoomExists", { name: "s".repeat(101) }],
    ["joinRooms com id texto", "/joinRooms", { idRoom: "abc", key: "k" }],
    ["joinRooms com id negativo", "/joinRooms", { idRoom: -1, key: "k" }],
    ["joinRooms com id fracionário", "/joinRooms", { idRoom: 1.5, key: "k" }],
    ["joinRooms com id acima do INTEGER", "/joinRooms", { idRoom: INT_MAX + 1, key: "k" }],
    ["joinRooms sem chave", "/joinRooms", { idRoom: 1 }],
    ["joinRooms com chave longa demais", "/joinRooms", { idRoom: 1, key: "k".repeat(129) }],
  ])("%s → 400", async (_label, path, body) => {
    const res = await alice.agent.post(path).send(body);
    expect(res.status).toBe(400);
    expect(res.body).toEqual(INVALID);
  });
});

describe("rotas de mensagem", () => {
  test.each(["abc", "0", "-1", "1.5", "1e3", String(INT_MAX + 1)])("GET /messages/%s → 400", async (id) => {
    const res = await alice.agent.get(`/messages/${id}`);
    expect(res.status).toBe(400);
    expect(res.body).toEqual(INVALID);
  });

  test("GET /roomUsers/abc → 400", async () => {
    const res = await alice.agent.get("/roomUsers/abc");
    expect(res.status).toBe(400);
    expect(res.body).toEqual(INVALID);
  });

  test.each([
    ["mensagem vazia", () => ({ room: roomId, message: "  " })],
    ["mensagem acima de 500 caracteres", () => ({ room: roomId, message: "m".repeat(501) })],
    ["mensagem não-string", () => ({ room: roomId, message: { texto: "oi" } })],
    ["sala como texto", () => ({ room: `${roomId}; DROP TABLE messages`, message: "oi" })],
    ["sala ausente", () => ({ message: "oi" })],
  ])("POST /messages com %s → 400", async (_label, body) => {
    const res = await alice.agent.post("/messages").send(body());
    expect(res.status).toBe(400);
    expect(res.body).toEqual(INVALID);
    expect((await pool.query("SELECT 1 FROM messages")).rowCount).toBe(0);
  });

  test.each([
    ["idLastMessage negativo", () => ({ room: roomId, idLastMessage: -5 })],
    ["idLastMessage texto", () => ({ room: roomId, idLastMessage: "x" })],
  ])("POST /updateLastViewed com %s → 400", async (_label, body) => {
    const res = await alice.agent.post("/updateLastViewed").send(body());
    expect(res.status).toBe(400);
    expect(res.body).toEqual(INVALID);
  });

  test("mensagem com exatamente 500 caracteres é aceita", async () => {
    const res = await alice.agent.post("/messages").send({ room: roomId, message: "m".repeat(500) });
    expect(res.status).toBe(201);
  });
});
