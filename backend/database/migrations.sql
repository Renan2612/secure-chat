-- Schema do secure-chat. Este script NÃO cria o banco: ele roda dentro do
-- banco já selecionado (no Docker, o POSTGRES_DB; manualmente, via
-- `psql -d secure_chat -f database/migrations.sql`).
--
-- CORRIGIDO (Etapa 2): o original fazia `CREATE DATABASE messagewebapp;
-- \c messagewebapp;`, então as tabelas iam parar num banco diferente do
-- DB_NAME usado pelo backend (secure_chat) e a aplicação não as encontrava.

DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS rooms_users;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS rooms;


CREATE TABLE IF NOT EXISTS rooms(
   id SERIAL PRIMARY KEY,
   name VARCHAR(255) NOT NULL,
   key VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS users(
   id SERIAL PRIMARY KEY,
   name VARCHAR(255) NOT NULL,
   email VARCHAR(255) NOT NULL,
   password VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS rooms_users (
   id SERIAL PRIMARY KEY,
   room INTEGER NOT NULL,
   user_id INTEGER NOT NULL,
   last_msg_viewed INTEGER NULL,
   FOREIGN KEY (user_id)
      REFERENCES users (id),
   FOREIGN KEY (room)
      REFERENCES rooms (id)
);

CREATE TABLE IF NOT EXISTS messages(
   id SERIAL PRIMARY KEY,
   room INTEGER NOT NULL,
   user_id INTEGER NOT NULL,
   message VARCHAR(500) NOT NULL,
   dt_message TIMESTAMP NOT NULL,
   FOREIGN KEY (user_id)
      REFERENCES users (id),
   FOREIGN KEY (room)
      REFERENCES rooms (id)
);