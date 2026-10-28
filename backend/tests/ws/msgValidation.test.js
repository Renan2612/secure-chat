// Validação do MSG_SEND: pacote fora do formato → ERROR BAD_REQUEST, sem
// derrubar a conexão na primeira ocorrência e sem gravar nada.
// (Recria os testes de validação do antigo POST /messages, removido com a
// rota, de tests/validation.test.js.)
const { pool, resetDb, createRoomInDb, fakeEnvelope } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, send } = require("./helpers");
const { MAX_BODY_BYTES } = require("../../realtime/protocol");

let srv;
let alice;
let room;

beforeEach(async () => {
  await resetDb();
  srv = await startServer();
  alice = await loginUser(srv, "alice");
  room = await createRoomInDb("Sala", [alice.id]);
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

const count = async () => Number((await pool.query("SELECT COUNT(*) FROM messages")).rows[0].count);

test("limite do body é 8192 bytes (igual ao CHECK da coluna)", () => {
  expect(MAX_BODY_BYTES).toBe(8192);
});

test.each([
  ["mensagem vazia", () => ({ room, cid: "c", body: "" })],
  ["mensagem acima do limite (bytes, multibyte)", () => ({ room, cid: "c", body: "é".repeat(MAX_BODY_BYTES / 2 + 1) })],
  ["mensagem não-string", () => ({ room, cid: "c", body: { texto: "oi" } })],
  ["mensagem ausente", () => ({ room, cid: "c" })],
  ["mensagem com byte NUL", () => ({ room, cid: "c", body: "a\u0000b" })],
  ["sala como texto (tentativa de SQL injection)", () => ({ room: `${room}; DROP TABLE messages`, cid: "c", body: "oi" })],
  ["sala ausente", () => ({ cid: "c", body: "oi" })],
  ["sala acima do INTEGER do Postgres", () => ({ room: 2147483648, cid: "c", body: "oi" })],
  ["cid ausente", () => ({ room, body: "oi" })],
  ["cid vazio", () => ({ room, cid: "", body: "oi" })],
  ["cid longo demais", () => ({ room, cid: "c".repeat(65), body: "oi" })],
  ["cid com caracteres fora do permitido", () => ({ room, cid: "a b<script>", body: "oi" })],
  ["cid não-string", () => ({ room, cid: 42, body: "oi" })],
])("MSG_SEND com %s → ERROR BAD_REQUEST, nada gravado, conexão segue aberta", async (_label, payload) => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "MSG_SEND", id: "q1", ...payload() });
  expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "BAD_REQUEST", ref: "q1" });
  send(ws, { type: "PING" });
  await nextPacket(inbox, "PONG");
  expect(inbox.closed).toBeNull();
  expect(await count()).toBe(0);
  ws.close();
});

test("a tabela messages continua intacta após a tentativa de injeção", async () => {
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "MSG_SEND", room: `${room}; DROP TABLE messages`, cid: "c", body: "oi" });
  await nextPacket(inbox, "ERROR");
  await expect(pool.query("SELECT 1 FROM messages")).resolves.toBeDefined();
  ws.close();
});

// Etapa 4b: o body só é aceito como envelope E2EE v1 (tests/ws/e2eeMessages
// cobre os recusados). O maior envelope possível ainda cabe no limite.
test("o maior envelope possível (texto preenchido de 5888 bytes) cabe no limite do body e é aceito", async () => {
  const body = fakeEnvelope({ paddedBytes: 5888 });
  expect(Buffer.byteLength(body)).toBeLessThanOrEqual(MAX_BODY_BYTES);
  const { ws, inbox } = await connect(srv, alice.cookie);
  send(ws, { type: "MSG_SEND", room, cid: "max", body });
  await nextPacket(inbox, "MSG_ACK");
  const { rows } = await pool.query("SELECT message FROM messages");
  expect(rows).toEqual([{ message: body }]);
  ws.close();
});
