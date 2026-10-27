// Ataque: coleta de informação — rotas de debug, enumeração, vazamento de
// hash de senha / chave de sala nas respostas e detalhes internos em erros.
const request = require("supertest");
const { app, pool, resetDb, createUser } = require("./helpers");

beforeEach(resetDb);
afterEach(() => jest.restoreAllMocks());
afterAll(() => pool.end());

describe("rotas removidas não existem (404), mesmo com sessão válida", () => {
  test.each([
    ["post", "/session"],
    ["get", "/session"],
    ["post", "/sessionRoom"],
    ["get", "/sessionRoom"],
    ["post", "/checkUserExists"],
    ["get", "/listRoomsNotInto"],
    ["get", "/logout"],
  ])("%s %s → 404", async (method, path) => {
    const { agent } = await createUser("alice");
    const res = await agent[method](path).send({ userId: 1 });
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ message: "Não encontrado" });
  });
});

test("nenhuma resposta da API contém hash de senha nem room.key (exceto createRoom)", async () => {
  const alice = await createUser("alice");
  const bob = await createUser("bob");
  const responses = [];
  const record = (label) => (res) => {
    responses.push({ label, text: res.text });
    return res;
  };

  const created = await alice.agent.post("/createRoom").send({ name: "Sala" });
  const { key, id: roomId } = created.body;
  expect(key).toMatch(/^[0-9a-f]{32}$/);

  await request(app)
    .post("/register")
    .send({ email: "carol@example.com", password: "senha-forte-de-teste", name: "Carol" })
    .then(record("register"));
  await request(app)
    .post("/login")
    .send({ email: alice.email, password: "senha-forte-de-teste" })
    .then(record("login ok"));
  await request(app)
    .post("/login")
    .send({ email: alice.email, password: "senha-errada-123" })
    .then(record("login falho"));
  await bob.agent.post("/joinRooms").send({ idRoom: roomId, key }).then(record("joinRooms"));
  await bob.agent.post("/joinRooms").send({ idRoom: roomId, key: "x" }).then(record("joinRooms 403"));
  await alice.agent.post("/messages").send({ room: roomId, message: "oi" }).then(record("POST /messages"));
  await alice.agent.get("/rooms").then(record("GET /rooms"));
  await alice.agent.get(`/messages/${roomId}`).then(record("GET /messages"));
  await alice.agent.get(`/roomUsers/${roomId}`).then(record("GET /roomUsers"));
  await alice.agent.post("/checkRoomExists").send({ name: "Sala" }).then(record("checkRoomExists"));
  await alice.agent
    .post("/updateLastViewed")
    .send({ room: roomId, idLastMessage: 1 })
    .then(record("updateLastViewed"));
  await bob.agent.get(`/messages/${roomId + 1}`).then(record("403"));
  await alice.agent.post("/logout").then(record("logout"));

  const { rows } = await pool.query("SELECT password FROM users");
  const hashes = rows.map((r) => r.password);
  for (const { label, text } of responses) {
    expect({ label, leaksHash: /\$2[aby]\$\d{2}\$/.test(text) }).toEqual({ label, leaksHash: false });
    for (const hash of hashes) expect(text).not.toContain(hash);
    expect({ label, leaksKey: text.includes(key) }).toEqual({ label, leaksKey: false });
    expect(text).not.toMatch(/"(password|key)"/);
  }
});

describe("erros não vazam detalhes internos", () => {
  test("falha do banco vira 500 genérico, sem mensagem/stack do Postgres", async () => {
    const { agent } = await createUser("alice");
    jest.spyOn(console, "error").mockImplementation(() => {});
    jest
      .spyOn(pool, "query")
      .mockRejectedValueOnce(Object.assign(new Error('relation "tabela_secreta" does not exist'), { code: "42P01" }));

    const res = await agent.get("/rooms");
    expect(res.status).toBe(500);
    expect(res.body).toEqual({ message: "Erro interno" });
    expect(res.text).not.toMatch(/tabela_secreta|42P01|at /);
  });

  test("falha ao obter conexão no createRoom responde 500 (não fica pendurado)", async () => {
    const { agent } = await createUser("alice");
    jest.spyOn(console, "error").mockImplementation(() => {});
    // Só a forma promise (usada pelo createRoom) falha; a forma com callback
    // é usada internamente pelo pool.query (ex.: carregar a sessão) e segue normal.
    const realConnect = pool.connect.bind(pool);
    jest
      .spyOn(pool, "connect")
      .mockImplementation((callback) =>
        callback ? realConnect(callback) : Promise.reject(new Error("pool esgotado"))
      );
    const res = await agent.post("/createRoom").send({ name: "Sala" });
    expect(res.status).toBe(500);
    expect(res.body).toEqual({ message: "Erro interno" });
  });

  test("o log de erro não contém senha, cookie nem corpo da requisição", async () => {
    const { agent, email } = await createUser("alice");
    const logged = [];
    const capture = (...args) => logged.push(args.map(String).join(" "));
    jest.spyOn(console, "error").mockImplementation(capture);
    jest.spyOn(console, "log").mockImplementation(capture);
    jest.spyOn(console, "warn").mockImplementation(capture);
    jest.spyOn(pool, "query").mockRejectedValueOnce(
      Object.assign(new Error("falha simulada"), { detail: `Key (email)=(${email}) already exists.` })
    );

    const res = await agent
      .post("/login")
      .send({ email, password: "senha-ultra-secreta-123" });
    expect(res.status).toBe(500);

    const output = logged.join("\n");
    expect(output).toContain("falha simulada"); // o erro é registrado...
    expect(output).not.toContain("senha-ultra-secreta-123"); // ...mas sem dados sensíveis
    expect(output).not.toContain(email);
    expect(output).not.toMatch(/sid=|cookie/i);
  });

  test("JSON malformado → 400 genérico em JSON (sem stack trace)", async () => {
    const res = await request(app)
      .post("/login")
      .set("Content-Type", "application/json")
      .send('{"email": "a@example.com", "password": ');
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ message: "Requisição inválida" });
    expect(res.text).not.toMatch(/SyntaxError|at /);
  });

  test("corpo acima de 10kb → 413 genérico em JSON", async () => {
    const res = await request(app)
      .post("/login")
      .send({ email: "a@example.com", password: "x".repeat(20 * 1024) });
    expect(res.status).toBe(413);
    expect(res.body).toEqual({ message: "Requisição muito grande" });
  });
});
