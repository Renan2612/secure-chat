// Ataque (item C): membro legítimo da sala tenta forjar o remetente,
// enviando o ID de outro usuário no corpo de POST /messages.
const { pool, resetDb, createUser, createRoomInDb } = require("./helpers");

let alice;
let bob;
let roomId;

beforeEach(async () => {
  await resetDb();
  alice = await createUser("alice");
  bob = await createUser("bob");
  roomId = await createRoomInDb("Sala compartilhada", [alice.id, bob.id]);
});

afterAll(() => pool.end());

test("user.id forjado no corpo é ignorado: a mensagem é gravada com o id da sessão", async () => {
  const res = await bob.agent
    .post("/messages")
    .send({ room: roomId, message: "eu sou a alice", user: { id: alice.id }, user_id: alice.id });

  expect(res.status).toBe(201);
  const { rows } = await pool.query("SELECT user_id FROM messages WHERE message = 'eu sou a alice'");
  expect(rows).toEqual([{ user_id: bob.id }]);
});

test("a resposta informa o remetente real (da sessão)", async () => {
  const res = await bob.agent
    .post("/messages")
    .send({ room: roomId, message: "oi", user: { id: alice.id } });
  expect(res.status).toBe(201);
  expect(res.body).toMatchObject({ room: roomId, user_id: bob.id, message: "oi" });
});

test("membro posta normalmente sem informar remetente", async () => {
  const res = await alice.agent.post("/messages").send({ room: roomId, message: "olá" });
  expect(res.status).toBe(201);
  const { rows } = await pool.query("SELECT user_id, room FROM messages");
  expect(rows).toEqual([{ user_id: alice.id, room: roomId }]);
});
