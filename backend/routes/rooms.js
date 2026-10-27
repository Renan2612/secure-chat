const crypto = require("crypto");
const pool = require("../db");

const getRooms = (req, res) => {
  const userId = req.session.userId;
  pool
    .query(
      `SELECT distinct rooms.id, rooms.name,  (SELECT COUNT(*) FROM messages WHERE room = rooms.id AND id > rooms_users.last_msg_viewed) as nummessages FROM rooms
    JOIN rooms_users
    ON rooms.id = rooms_users.room
    WHERE rooms_users.user_id = $1
    `,
      [userId]
    )
    .then((result) => result.rows)
    .then((messages) => {
      res.status(200).json(messages);
    })
    .catch((err) => {
      console.log("err", err);
      res.status(500).json({ message: "Erro ao buscar salas" });
    });
};

const checkRoomExists = (req, res) => {
  const name = req.body.name;
  pool
    .query("SELECT id, name FROM rooms WHERE name = $1", [name])
    .then((resp) => {
      res.status(200).json(resp.rows);
    })
    .catch((err) => {
      console.log("err", err);
      res.status(500).json({ message: "Erro ao verificar sala" });
    });
};

// CORRIGIDO: a chave de convite era o literal fixo "41421" para TODAS as
// salas. Agora é gerada aleatoriamente por sala. A VALIDAÇÃO dessa chave em
// joinRooms continua pendente para a Etapa 2 — hoje ela ainda não é checada.
const createRooms = (req, res) => {
  const name = req.body.name;
  const key = crypto.randomBytes(8).toString("hex");

  pool
    .query(`INSERT INTO rooms (name, key) VALUES ($1, $2) returning id, name;`, [name, key])
    .then((result) => result.rows)
    .then((rooms) => {
      res.status(200).json(rooms);
    })
    .catch((err) => {
      console.log("err", err);
      res.status(500).json({ message: "Erro ao criar sala" });
    });
};

const listRoomsNotInto = (req, res) => {
  const userId = req.session.userId;
  pool
    .query(
      `select id, name from rooms where not exists (select 1 from rooms_users where rooms.id = rooms_users.room AND rooms_users.user_id = $1)`,
      [userId]
    )
    .then((resp) => {
      res.status(200).json(resp.rows);
    })
    .catch((err) => {
      console.log("err", err);
      res.status(500).json({ message: "Erro ao listar salas" });
    });
};

// ATENÇÃO (Etapa 2): não valida a chave de convite da sala (room.key) nem
// qualquer outra permissão — qualquer usuário autenticado entra em qualquer
// sala apenas sabendo o idRoom. Mantido assim de propósito como linha de
// base. Ver docs/01-baseline-seguranca.md.
const joinRooms = (req, res) => {
  const room = req.body.idRoom;
  const user_id = req.session.userId;
  pool
    .query(
      `INSERT INTO rooms_users (room, user_id, last_msg_viewed ) VALUES ($1, $2, 0) returning *;
    `,
      [room, user_id]
    )
    .then((result) => result.rows)
    .then((rooms) => {
      res.status(200).json(rooms);
    })
    .catch((err) => {
      console.log("err", err);
      res.status(500).json({ message: "Erro ao entrar na sala" });
    });
};

// Pertencimento à sala verificado antes, pelo middleware requireRoomMember.
const roomsUsers = (req, res) => {
  const room = req.params.room;
  pool
    .query(
      `SELECT users.name, users.id
      FROM rooms_users 
      JOIN users
      ON user_id = users.id
      WHERE room = $1;
    `,
      [room]
    )
    .then((result) => result.rows)
    .then((rooms) => {
      res.status(200).json(rooms);
    })
    .catch((err) => {
      console.log("err", err);
      res.status(500).json({ message: "Erro ao listar membros" });
    });
};

module.exports = { getRooms, createRooms, joinRooms, checkRoomExists, listRoomsNotInto, roomsUsers };
