const request = require("./request");
const pool = require("../db");
const { createApp } = require("../app");

// Limite alto: os testes fazem muitos logins seguidos a partir do mesmo IP.
// O comportamento dos rate limits em si é testado com um app próprio (login.test.js).
const app = createApp({ authRateLimitMax: 10000, loginEmailRateLimitMax: 10000 });

const PASSWORD = "senha-forte-de-teste";

const resetDb = () =>
  pool.query("TRUNCATE user_sessions, room_bans, room_key_wraps, room_key_versions, user_keys, messages, rooms_users, rooms, users RESTART IDENTITY CASCADE");

let counter = 0;

// Cadastra um usuário novo e devolve um agente supertest já autenticado
// (o agente guarda o cookie de sessão entre requisições).
const createUser = async (name = "user") => {
  counter += 1;
  const email = `${name}${counter}@example.com`;
  const reg = await request(app).post("/register").send({ email, password: PASSWORD, name });
  if (reg.status !== 201) throw new Error(`register falhou: ${reg.status} ${JSON.stringify(reg.body)}`);
  const agent = request.agent(app);
  const login = await agent.post("/login").send({ email, password: PASSWORD });
  if (login.status >= 300) throw new Error(`login falhou: ${login.status} ${JSON.stringify(login.body)}`);
  return { agent, id: reg.body.id, email, loginResponse: login };
};

// Inscreve o usuário na sala direto no banco (sem passar pela API).
const addMember = (roomId, userId) =>
  pool.query("INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)", [
    roomId,
    userId,
  ]);

// Cria uma sala direto no banco (sem passar pela API) e inscreve os membros;
// o primeiro membro é o criador e dono (rooms.created_by e owner_id). O
// primeiro argumento é só um rótulo para o teste: desde a Etapa 5 o nome
// da sala não vai ao banco em claro (name_env fica null até a v1).
const createRoomInDb = async (_label, memberIds) => {
  if (!memberIds?.length) throw new Error("createRoomInDb: informe ao menos o criador");
  const { rows } = await pool.query(
    "INSERT INTO rooms (invite_hash, created_by, owner_id) VALUES ($1, $2, $2) RETURNING id",
    ["0".repeat(64), memberIds[0]]
  );
  for (const userId of memberIds) {
    await addMember(rows[0].id, userId);
  }
  return rows[0].id;
};

const b64 = (n) => require("node:crypto").randomBytes(n).toString("base64url");

// Envelope E2EE v2 ESTRUTURALMENTE válido, com bytes aleatórios no lugar do
// texto cifrado: o servidor só confere a estrutura (realtime/envelope.js),
// então serve para os testes que não decifram. `paddedBytes` = tamanho do
// texto claro preenchido (múltiplo de 128); `exp` = segundos Unix ou null.
// Os testes que decifram usam shared/e2ee de verdade (tests/e2ee/,
// tests/ws/e2eeMessages.test.js).
const fakeEnvelope = ({ kv = 1, paddedBytes = 128, exp = null } = {}) =>
  JSON.stringify({ v: 2, kv, iv: b64(12), ct: b64(paddedBytes + 16), sig: b64(64), exp });

// Nome da sala cifrado, só na ESTRUTURA (o servidor não decifra).
const fakeNameEnv = (kv = 1) => JSON.stringify({ v: 1, kv, iv: b64(12), ct: b64(128 + 16) });

// Grava uma mensagem direto no banco. `label` vira o cid (os testes de
// histórico conferem a ordem pelos cids, já que o body é cifrado). O
// expires_at acompanha o exp do envelope (CHECK do banco).
const insertMessage = async (roomId, userId, label, body = fakeEnvelope()) => {
  const cid = String(label).replace(/[^A-Za-z0-9_-]/g, "-").slice(0, 64);
  let exp = null;
  try {
    exp = JSON.parse(body).exp ?? null;
  } catch {
    // texto puro: os testes da falha fechada do banco
  }
  const { rows } = await pool.query(
    `INSERT INTO messages (room, user_id, message, cid, key_version, expires_at)
     VALUES ($1, $2, $3, $4, 1, to_timestamp($5::double precision)) RETURNING id`,
    [roomId, userId, body, cid, exp ?? null]
  );
  return rows[0].id;
};

// Faz pool.query falhar só para o SQL que casa com `pattern` (as demais
// consultas — ex.: a leitura da sessão pelo connect-pg-simple, que usa o
// mesmo pool — seguem normais). Devolve um contador de falhas injetadas,
// para o teste provar que a rota-alvo foi de fato alcançada.
const failQueriesMatching = (pattern, error, times = 1) => {
  const realQuery = pool.query.bind(pool);
  const injected = { count: 0 };
  jest.spyOn(pool, "query").mockImplementation((text, ...rest) => {
    const sql = typeof text === "string" ? text : text && text.text;
    if (injected.count < times && pattern.test(sql || "")) {
      injected.count += 1;
      return Promise.reject(error);
    }
    return realQuery(text, ...rest);
  });
  return injected;
};

module.exports = {
  app,
  pool,
  resetDb,
  createUser,
  addMember,
  createRoomInDb,
  insertMessage,
  fakeEnvelope,
  fakeNameEnv,
  failQueriesMatching,
  PASSWORD,
};
