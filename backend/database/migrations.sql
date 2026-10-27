-- Schema do secure-chat. Este script NÃO cria o banco: ele roda dentro do
-- banco já selecionado (no Docker, o POSTGRES_DB; manualmente, via
-- `psql -d secure_chat -f database/migrations.sql`).
--
-- CORRIGIDO (Etapa 2): o original fazia `CREATE DATABASE messagewebapp;
-- \c messagewebapp;`, então as tabelas iam parar num banco diferente do
-- DB_NAME usado pelo backend (secure_chat) e a aplicação não as encontrava.

DROP TABLE IF EXISTS user_sessions;
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
   -- Único e sempre em minúsculas (a API normaliza antes de gravar; o
   -- CHECK impede que uma inserção fora da API crie "duplicatas" por caixa).
   email VARCHAR(254) NOT NULL UNIQUE CHECK (email = LOWER(email)),
   password VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS rooms_users (
   id SERIAL PRIMARY KEY,
   room INTEGER NOT NULL,
   user_id INTEGER NOT NULL,
   last_msg_viewed INTEGER NULL,
   -- Um vínculo por (sala, usuário): entrar duas vezes não duplica a linha.
   UNIQUE (room, user_id),
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

-- Sessões armazenadas no servidor (express-session + connect-pg-simple).
-- O cookie do cliente carrega só o ID assinado; os dados ficam aqui, o que
-- permite revogar uma sessão apagando a linha (logout, troca de senha...).
-- Estrutura exigida pelo connect-pg-simple (node_modules/connect-pg-simple/table.sql).
CREATE TABLE IF NOT EXISTS user_sessions (
   sid VARCHAR NOT NULL COLLATE "default" PRIMARY KEY,
   sess JSON NOT NULL,
   expire TIMESTAMP(6) NOT NULL
);

CREATE INDEX IF NOT EXISTS user_sessions_expire_idx ON user_sessions (expire);
