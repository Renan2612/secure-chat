CREATE DATABASE messagewebapp;
\c messagewebapp;

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