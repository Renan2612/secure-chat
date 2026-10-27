const request = require("supertest");
const pool = require("../db");
const { createApp } = require("../app");

// Limite alto: os testes fazem muitos logins seguidos a partir do mesmo IP.
// O comportamento dos rate limits em si é testado com um app próprio (login.test.js).
const app = createApp({ authRateLimitMax: 10000, loginEmailRateLimitMax: 10000 });

const PASSWORD = "senha-forte-de-teste";

const resetDb = () =>
  pool.query("TRUNCATE user_sessions, messages, rooms_users, rooms, users RESTART IDENTITY CASCADE");

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

// Cria uma sala direto no banco (sem passar pela API) e inscreve os membros.
const createRoomInDb = async (name, memberIds = []) => {
  const { rows } = await pool.query(
    "INSERT INTO rooms (name, key) VALUES ($1, $2) RETURNING id",
    [name, "chave-da-sala-de-teste"]
  );
  for (const userId of memberIds) {
    await addMember(rows[0].id, userId);
  }
  return rows[0].id;
};

const insertMessage = async (roomId, userId, text) => {
  const { rows } = await pool.query(
    "INSERT INTO messages (room, user_id, message, dt_message) VALUES ($1, $2, $3, NOW()) RETURNING id",
    [roomId, userId, text]
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
  failQueriesMatching,
  PASSWORD,
};
