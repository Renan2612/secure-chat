// Variáveis de ambiente dos testes. Apontam para o Postgres descartável do
// docker-compose.test.yml (porta 5433), nunca para o banco de desenvolvimento.
// Cada uma pode ser sobrescrita pelo ambiente (ex.: em CI).
const defaults = {
  NODE_ENV: "test",
  DB_USER: "postgres",
  DB_PASSWORD: "postgres_test",
  DB_HOST: "127.0.0.1",
  DB_PORT: "5433",
  DB_NAME: "secure_chat_test",
  SESSION_SECRET: "segredo-de-sessao-usado-apenas-nos-testes-0123456789",
  CLIENT_URL: "http://localhost:3000",
  // Custo baixo só nos testes (ver helpers/users.js); login.test.js volta
  // para 12 porque mede a equalização de tempo do login.
  BCRYPT_COST: "4",
};

for (const [name, value] of Object.entries(defaults)) {
  if (process.env[name] === undefined) process.env[name] = value;
}
