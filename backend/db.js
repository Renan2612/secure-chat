// Pool único, compartilhado por toda a aplicação.
//
// O projeto original criava um `new Pool(...)` dentro de CADA função de rota
// e chamava `pool.end()` no final — ou seja, abria e fechava a conexão com o
// banco a cada requisição. Isso funciona, mas é caro e desnecessário; o
// padrão correto é manter um único pool vivo durante toda a vida do processo.
//
// Também corrige um bug de configuração: o código original usava
// `process.env.DB_NAME` como o USUÁRIO do banco (campo `user`), quando na
// verdade DB_NAME deveria ser o nome do banco. Aqui os nomes das variáveis
// foram padronizados: DB_USER, DB_HOST, DB_NAME, DB_PASSWORD, DB_PORT.
const { Pool } = require("pg");

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

pool.on("error", (err) => {
  console.error("Erro inesperado no pool do Postgres:", err);
});

module.exports = pool;
