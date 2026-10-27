// Recria o schema do banco de teste uma vez antes da suíte, a partir da
// mesma migrations.sql usada em produção.
const fs = require("fs");
const path = require("path");
const { Client } = require("pg");

module.exports = async () => {
  require("./env");
  const client = new Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
  });
  try {
    await client.connect();
  } catch (err) {
    throw new Error(
      `Banco de teste inacessível em ${process.env.DB_HOST}:${process.env.DB_PORT} (${err.message}). ` +
        "Suba-o com: docker compose -f docker-compose.test.yml up -d"
    );
  }
  const sql = fs.readFileSync(path.join(__dirname, "..", "database", "migrations.sql"), "utf8");
  await client.query("SET client_min_messages TO WARNING");
  await client.query(sql);
  await client.end();
};
