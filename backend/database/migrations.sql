-- Schema do secure-chat. Este script NÃO cria o banco: ele roda dentro do
-- banco já selecionado (no Docker, o POSTGRES_DB; manualmente, via
-- `psql -d secure_chat -f database/migrations.sql`).
--
-- CORRIGIDO (Etapa 2): o original fazia `CREATE DATABASE messagewebapp;
-- \c messagewebapp;`, então as tabelas iam parar num banco diferente do
-- DB_NAME usado pelo backend (secure_chat) e a aplicação não as encontrava.

DROP VIEW IF EXISTS room_current_wraps;
DROP TABLE IF EXISTS room_key_wraps;
DROP TABLE IF EXISTS room_key_versions;
DROP TABLE IF EXISTS user_keys;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS rooms_users;
DROP TABLE IF EXISTS rooms;
DROP TABLE IF EXISTS users;


CREATE TABLE IF NOT EXISTS users(
   id SERIAL PRIMARY KEY,
   name VARCHAR(255) NOT NULL,
   -- Único e sempre em minúsculas (a API normaliza antes de gravar; o
   -- CHECK impede que uma inserção fora da API crie "duplicatas" por caixa).
   email VARCHAR(254) NOT NULL UNIQUE CHECK (email = LOWER(email)),
   password VARCHAR(255) NOT NULL
);

-- `key` é a chave de CONVITE (Etapa 2), não a chave de cifragem da sala.
-- key_version: versão atual da chave da sala (E2EE, docs/05-e2ee.md); nesta
-- etapa é sempre 1 (rotação de chave fica para a 4b-2).
CREATE TABLE IF NOT EXISTS rooms(
   id SERIAL PRIMARY KEY,
   name VARCHAR(255) NOT NULL,
   key VARCHAR(255) NOT NULL,
   created_by INTEGER NOT NULL REFERENCES users (id),
   key_version INTEGER NOT NULL DEFAULT 1 CHECK (key_version >= 1)
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
   -- Conteúdo OPACO para o servidor (na Etapa 4, texto cifrado). Limite em
   -- BYTES igual ao maxBodyBytes do protocolo (realtime/protocol.js).
   message TEXT NOT NULL CHECK (octet_length(message) BETWEEN 1 AND 8192),
   dt_message TIMESTAMPTZ NOT NULL DEFAULT NOW(),
   -- ID gerado pelo cliente para idempotência (MSG_SEND): reenviar com o
   -- mesmo cid não duplica. Único por remetente; NULL fora do protocolo.
   cid VARCHAR(64) NULL,
   UNIQUE (user_id, cid),
   FOREIGN KEY (user_id)
      REFERENCES users (id),
   FOREIGN KEY (room)
      REFERENCES rooms (id)
);

-- Versões publicadas da chave da sala (D4). A chave em si NUNCA vem para
-- cá: só existe embrulhada (room_key_wraps) para cada membro.
CREATE TABLE IF NOT EXISTS room_key_versions (
   room INTEGER NOT NULL REFERENCES rooms (id),
   version INTEGER NOT NULL CHECK (version >= 1),
   created_by INTEGER NOT NULL REFERENCES users (id),
   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
   PRIMARY KEY (room, version)
);

-- Um wrap por (sala, versão, destinatário): a chave da sala cifrada para a
-- chave pública ECDH do destinatário (ECDH efêmero + HKDF + AES-GCM) e
-- assinada pelo remetente. Tamanhos fixos em base64url sem padding:
-- iv 12 B → 16; wrapped 32 B + tag 16 B → 64; sig r||s 64 B → 86.
CREATE TABLE IF NOT EXISTS room_key_wraps (
   room INTEGER NOT NULL,
   version INTEGER NOT NULL,
   recipient_id INTEGER NOT NULL REFERENCES users (id),
   sender_id INTEGER NOT NULL REFERENCES users (id),
   -- key_epoch do destinatário para o qual o wrap foi cifrado. Um wrap de
   -- época antiga (o destinatário trocou de chave) não conta como chave e
   -- pode ser substituído (ver room_current_wraps).
   recipient_key_epoch INTEGER NOT NULL CHECK (recipient_key_epoch >= 1),
   eph_pub VARCHAR(200) NOT NULL CHECK (eph_pub ~ '^[A-Za-z0-9_-]+$'),
   iv CHAR(16) NOT NULL CHECK (iv ~ '^[A-Za-z0-9_-]{16}$'),
   wrapped CHAR(64) NOT NULL CHECK (wrapped ~ '^[A-Za-z0-9_-]{64}$'),
   sig CHAR(86) NOT NULL CHECK (sig ~ '^[A-Za-z0-9_-]{86}$'),
   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
   PRIMARY KEY (room, version, recipient_id),
   FOREIGN KEY (room, version) REFERENCES room_key_versions (room, version)
);

-- Diretório de chaves PÚBLICAS da E2EE (docs/05-e2ee.md, D3). As privadas
-- nunca saem do cliente. SPKI P-256 em base64url (122 caracteres), validado
-- pela API. fingerprint = SHA-256 calculado pelo servidor (shared/e2ee).
-- key_epoch sobe a cada POST /keys/reset.
CREATE TABLE IF NOT EXISTS user_keys (
   user_id INTEGER PRIMARY KEY REFERENCES users (id),
   ecdh_pub VARCHAR(200) NOT NULL CHECK (ecdh_pub ~ '^[A-Za-z0-9_-]+$'),
   ecdsa_pub VARCHAR(200) NOT NULL CHECK (ecdsa_pub ~ '^[A-Za-z0-9_-]+$'),
   fingerprint CHAR(64) NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
   key_epoch INTEGER NOT NULL DEFAULT 1 CHECK (key_epoch >= 1),
   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
   CHECK (ecdh_pub <> ecdsa_pub)
);

-- Wraps que valem como "tem a chave atual da sala": versão atual da sala E
-- cifrados para a chave atual do destinatário. Toda checagem de autorização
-- de chave (pendentes, quem distribui, ROOM_EVENT) usa esta view.
CREATE VIEW room_current_wraps AS
   SELECT w.* FROM room_key_wraps w
   JOIN rooms r ON r.id = w.room AND r.key_version = w.version
   JOIN user_keys k ON k.user_id = w.recipient_id AND k.key_epoch = w.recipient_key_epoch;

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
