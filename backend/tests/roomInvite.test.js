// Ataque (item E): usuário B tenta entrar na sala de A sem conhecer a chave
// de convite, ou descobrir salas privadas pelas rotas de listagem.
const { pool, resetDb, createUser } = require("./helpers");

let alice;
let bob;
let room; // { id, key } devolvido a Alice no createRoom

beforeEach(async () => {
  await resetDb();
  alice = await createUser("alice");
  bob = await createUser("bob");
  const res = await alice.agent.post("/createRoom").send({});
  expect(res.status).toBe(201);
  room = res.body;
});

afterAll(() => pool.end());

const membership = async (roomId, userId) =>
  (await pool.query("SELECT 1 FROM rooms_users WHERE room = $1 AND user_id = $2", [roomId, userId]))
    .rowCount;

describe("createRoom", () => {
  test("devolve a chave de convite apenas ao criador, com 128 bits aleatórios", async () => {
    expect(room).toEqual({ id: expect.any(Number), key: expect.any(String) });
    expect(room.key).toMatch(/^[0-9a-f]{32}$/);
  });

  test("Etapa 5: nome em claro é RECUSADO (só chega cifrado, na publicação da v1)", async () => {
    const res = await alice.agent.post("/createRoom").send({ name: "Sala secreta" });
    expect(res.status).toBe(400);
    expect((await pool.query("SELECT COUNT(*)::int AS n FROM rooms")).rows[0].n).toBe(1);
    expect((await pool.query("SELECT name_env FROM rooms WHERE id = $1", [room.id])).rows[0].name_env).toBeNull();
  });

  test("criador entra automaticamente na sala", async () => {
    expect(await membership(room.id, alice.id)).toBe(1);
    expect((await alice.agent.get(`/messages/${room.id}`)).status).toBe(200);
  });

  test("cada sala recebe uma chave diferente", async () => {
    const other = (await alice.agent.post("/createRoom").send({})).body;
    expect(other.key).not.toBe(room.key);
  });
});

describe("joinRooms exige a chave de convite", () => {
  test("chave errada (mesmo tamanho) → 403 e B não vira membro", async () => {
    const wrong = room.key.replace(/./, (c) => (c === "0" ? "1" : "0"));
    const res = await bob.agent.post("/joinRooms").send({ idRoom: room.id, key: wrong });
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ message: "Convite inválido" });
    expect(await membership(room.id, bob.id)).toBe(0);
  });

  test("chave de tamanho diferente → 403 (sem erro do timingSafeEqual)", async () => {
    const res = await bob.agent.post("/joinRooms").send({ idRoom: room.id, key: "abc" });
    expect(res.status).toBe(403);
    expect(await membership(room.id, bob.id)).toBe(0);
  });

  test("chave de outra sala → 403", async () => {
    const bobsRoom = (await bob.agent.post("/createRoom").send({})).body;
    const res = await bob.agent.post("/joinRooms").send({ idRoom: room.id, key: bobsRoom.key });
    expect(res.status).toBe(403);
  });

  test("sala inexistente → mesma resposta 403 (não revela quais IDs existem)", async () => {
    const res = await bob.agent.post("/joinRooms").send({ idRoom: 999999, key: room.key });
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ message: "Convite inválido" });
  });

  test("chave certa → B entra e passa a ler a sala", async () => {
    const res = await bob.agent.post("/joinRooms").send({ idRoom: room.id, key: room.key });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ id: room.id });
    expect(await membership(room.id, bob.id)).toBe(1);
    expect((await bob.agent.get(`/messages/${room.id}`)).status).toBe(200);
  });

  test("entrar duas vezes não duplica o vínculo", async () => {
    await bob.agent.post("/joinRooms").send({ idRoom: room.id, key: room.key });
    const again = await bob.agent.post("/joinRooms").send({ idRoom: room.id, key: room.key });
    expect(again.status).toBe(200);
    expect(await membership(room.id, bob.id)).toBe(1);
  });
});

describe("descoberta de salas privadas", () => {
  test("listRoomsNotInto foi removida (listava todas as salas alheias)", async () => {
    const res = await bob.agent.get("/listRoomsNotInto");
    expect(res.status).toBe(404);
  });

  test("Etapa 5: a busca por nome (checkRoomExists) foi removida: o servidor não conhece os nomes", async () => {
    const res = await alice.agent.post("/checkRoomExists").send({ name: "Sala secreta" });
    expect(res.status).toBe(404);
  });
});

describe("createRoom é atômico e resiste a falhas de conexão", () => {
  afterEach(() => jest.restoreAllMocks());

  test("se a inscrição do criador falha, a sala não fica órfã", async () => {
    jest.spyOn(console, "error").mockImplementation(() => {});
    const carol = await createUser("carol");
    // Conta apagada com a sessão ainda ativa: o INSERT em rooms_users viola a FK.
    await pool.query("DELETE FROM users WHERE id = $1", [carol.id]);
    const res = await carol.agent.post("/createRoom").send({});
    expect(res.status).toBe(500);
    expect((await pool.query("SELECT COUNT(*)::int AS n FROM rooms")).rows[0].n).toBe(1); // só a da Alice
  });

  test("evento 'error' na conexão durante a transação não derruba o processo", async () => {
    jest.spyOn(console, "error").mockImplementation(() => {});
    const realConnect = pool.connect.bind(pool);
    jest.spyOn(pool, "connect").mockImplementation(async (callback) => {
      if (callback) return realConnect(callback);
      const client = await realConnect();
      // Simula a queda do socket enquanto a rota usa o client (após o await).
      setImmediate(() => client.emit("error", new Error("conexão caiu")));
      return client;
    });
    const res = await alice.agent.post("/createRoom").send({});
    expect([201, 500]).toContain(res.status);
  });
});
