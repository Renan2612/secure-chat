const request = require("supertest");
const pool = require("../db");
const { createApp } = require("../app");

// Limite alto: os testes fazem muitos logins seguidos a partir do mesmo IP.
// O comportamento do rate limit em si é testado com um app próprio.
const app = createApp({ authRateLimitMax: 10000 });

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

module.exports = { app, pool, resetDb, createUser, PASSWORD };
