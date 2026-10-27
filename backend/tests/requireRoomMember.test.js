// Ataque (item D, IDOR): usuário autenticado B tenta ler/escrever na sala
// de A, da qual não é membro, só trocando o ID da sala na requisição.
const { pool, resetDb, createUser, createRoomInDb, insertMessage } = require("./helpers");

let alice;
let bob;
let roomId;

beforeEach(async () => {
  await resetDb();
  alice = await createUser("alice");
  bob = await createUser("bob");
  roomId = await createRoomInDb("Sala privada da Alice", [alice.id]);
  await insertMessage(roomId, alice.id, "segredo da alice");
});

afterAll(() => pool.end());

describe("usuário B (não membro) é barrado com 403", () => {
  test("não lê as mensagens da sala alheia", async () => {
    const res = await bob.agent.get(`/messages/${roomId}`);
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ message: "Acesso negado" });
    expect(JSON.stringify(res.body)).not.toContain("segredo da alice");
  });

  test("não lista os membros da sala alheia", async () => {
    const res = await bob.agent.get(`/roomUsers/${roomId}`);
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ message: "Acesso negado" });
  });

  test("não posta mensagem na sala alheia", async () => {
    const res = await bob.agent.post("/messages").send({ room: roomId, message: "intruso" });
    expect(res.status).toBe(403);
    const { rows } = await pool.query("SELECT 1 FROM messages WHERE message = 'intruso'");
    expect(rows).toHaveLength(0);
  });

  test("não altera o marcador de leitura da sala alheia", async () => {
    const res = await bob.agent.post("/updateLastViewed").send({ room: roomId, idLastMessage: 1 });
    expect(res.status).toBe(403);
  });

  test.each([
    ["GET /messages", (a) => a.get("/messages/999999")],
    ["GET /roomUsers", (a) => a.get("/roomUsers/999999")],
    ["POST /messages", (a) => a.post("/messages").send({ room: 999999, message: "oi" })],
    ["POST /updateLastViewed", (a) => a.post("/updateLastViewed").send({ room: 999999, idLastMessage: 1 })],
  ])("sala inexistente em %s → mesma resposta 403 (não revela quais IDs existem)", async (_l, send) => {
    const res = await send(bob.agent);
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ message: "Acesso negado" });
    expect((await pool.query("SELECT 1 FROM messages WHERE room = 999999")).rowCount).toBe(0);
  });

  test("GET /rooms não lista a sala alheia", async () => {
    const res = await bob.agent.get("/rooms");
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });

  test("tentativa negada não altera o marcador de leitura da dona da sala", async () => {
    await bob.agent.post("/updateLastViewed").send({ room: roomId, idLastMessage: 42 });
    const { rows } = await pool.query("SELECT last_msg_viewed FROM rooms_users WHERE user_id = $1", [alice.id]);
    expect(rows).toEqual([{ last_msg_viewed: 0 }]);
  });
});

describe("membro da sala continua com acesso", () => {
  test("lê as mensagens da própria sala, e só dela", async () => {
    const bobsRoom = await createRoomInDb("Sala do Bob", [bob.id]);
    await insertMessage(bobsRoom, bob.id, "segredo do bob");
    const res = await alice.agent.get(`/messages/${roomId}`);
    expect(res.status).toBe(200);
    expect(res.body.map((m) => m.message)).toEqual(["segredo da alice"]);
  });

  test("lista os membros da própria sala, e só dela", async () => {
    await createRoomInDb("Sala do Bob", [bob.id]);
    const res = await alice.agent.get(`/roomUsers/${roomId}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual([{ id: alice.id, name: "alice" }]);
  });

  test("GET /rooms lista a sala depois que B vira membro", async () => {
    await pool.query("INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)", [
      roomId,
      bob.id,
    ]);
    const res = await bob.agent.get("/rooms");
    expect(res.body.map((r) => r.id)).toEqual([roomId]);
  });

  test("updateLastViewed altera só o próprio marcador, mesmo com user_id forjado", async () => {
    await pool.query("INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)", [
      roomId,
      bob.id,
    ]);
    const res = await alice.agent
      .post("/updateLastViewed")
      .send({ room: roomId, idLastMessage: 7, user_id: bob.id, user: { id: bob.id } });
    expect(res.status).toBe(200);
    const { rows } = await pool.query(
      "SELECT user_id, last_msg_viewed FROM rooms_users WHERE room = $1 ORDER BY user_id",
      [roomId]
    );
    expect(rows).toEqual([
      { user_id: alice.id, last_msg_viewed: 7 },
      { user_id: bob.id, last_msg_viewed: 0 },
    ]);
  });

  test("atualiza o próprio marcador de leitura", async () => {
    const res = await alice.agent.post("/updateLastViewed").send({ room: roomId, idLastMessage: 1 });
    expect(res.status).toBe(200);
  });

  test("ao virar membro, B passa a ter acesso", async () => {
    await pool.query("INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)", [
      roomId,
      bob.id,
    ]);
    expect((await bob.agent.get(`/messages/${roomId}`)).status).toBe(200);
  });
});

test("ler mensagens não grava a sala na sessão do usuário", async () => {
  await alice.agent.get(`/messages/${roomId}`);
  const { rows } = await pool.query("SELECT sess FROM user_sessions");
  for (const { sess } of rows) expect(sess).not.toHaveProperty("room");
});
