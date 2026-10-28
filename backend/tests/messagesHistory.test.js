// Item 5: um único caminho de envio (MSG_SEND no /ws). O HTTP fica só com a
// leitura do histórico, paginada e com limite máximo.
const { pool, resetDb, createUser, createRoomInDb, insertMessage } = require("./helpers");

let alice;
let roomId;
let ids;

beforeEach(async () => {
  await resetDb();
  alice = await createUser("alice");
  roomId = await createRoomInDb("Sala", [alice.id]);
  ids = [];
  for (let i = 1; i <= 5; i += 1) ids.push(await insertMessage(roomId, alice.id, `m${i}`));
});

afterAll(() => pool.end());

test("POST /messages não existe mais (404): envio só pelo WebSocket", async () => {
  const res = await alice.agent.post("/messages").send({ room: roomId, message: "oi" });
  expect(res.status).toBe(404);
  expect((await pool.query("SELECT 1 FROM messages WHERE message = 'oi'")).rowCount).toBe(0);
});

describe("GET /messages/:id paginado", () => {
  const texts = (res) => res.body.map((m) => m.message);

  test("sem parâmetros: as mais recentes, em ordem cronológica", async () => {
    const res = await alice.agent.get(`/messages/${roomId}`);
    expect(res.status).toBe(200);
    expect(texts(res)).toEqual(["m1", "m2", "m3", "m4", "m5"]);
  });

  test("limit devolve só as N mais recentes", async () => {
    const res = await alice.agent.get(`/messages/${roomId}?limit=2`);
    expect(texts(res)).toEqual(["m4", "m5"]);
  });

  test("before pagina para trás (mensagens com id menor)", async () => {
    const res = await alice.agent.get(`/messages/${roomId}?limit=2&before=${ids[3]}`);
    expect(texts(res)).toEqual(["m2", "m3"]);
  });

  test("padrão de 50 e máximo de 100", async () => {
    for (let i = 6; i <= 120; i += 1) await insertMessage(roomId, alice.id, `m${i}`);
    expect((await alice.agent.get(`/messages/${roomId}`)).body).toHaveLength(50);
    expect((await alice.agent.get(`/messages/${roomId}?limit=100`)).body).toHaveLength(100);
  });

  test.each(["limit=101", "limit=0", "limit=abc", "before=0", "before=-1", "before=x"])(
    "?%s → 400",
    async (query) => {
      const res = await alice.agent.get(`/messages/${roomId}?${query}`);
      expect(res.status).toBe(400);
      expect(res.body).toEqual({ message: "Requisição inválida" });
    }
  );
});

describe("coluna messages.message comporta o body opaco do protocolo", () => {
  test("aceita até 8192 bytes", async () => {
    await expect(insertMessage(roomId, alice.id, "x".repeat(8192))).resolves.toEqual(expect.any(Number));
  });

  test("recusa acima de 8192 bytes (multibyte conta em bytes)", async () => {
    await expect(insertMessage(roomId, alice.id, "é".repeat(4097))).rejects.toThrow(/check/i);
  });
});
