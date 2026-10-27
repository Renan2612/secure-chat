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

  test("sala inexistente recebe a mesma resposta (não revela quais IDs existem)", async () => {
    const res = await bob.agent.get(`/messages/999999`);
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ message: "Acesso negado" });
  });
});

describe("membro da sala continua com acesso", () => {
  test("lê as mensagens da própria sala", async () => {
    const res = await alice.agent.get(`/messages/${roomId}`);
    expect(res.status).toBe(200);
    expect(res.body.map((m) => m.message)).toEqual(["segredo da alice"]);
  });

  test("lista os membros da própria sala", async () => {
    const res = await alice.agent.get(`/roomUsers/${roomId}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual([{ id: alice.id, name: "alice" }]);
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
