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

// Busca só entre as salas das quais o usuário já é membro (uso: avisar que
// ele já tem uma sala com esse nome). CORRIGIDO: antes buscava em TODAS as
// salas e revelava nome e ID de salas privadas de terceiros.
const checkRoomExists = (req, res) => {
  const name = req.body.name;
  pool
    .query(
      `SELECT rooms.id, rooms.name FROM rooms
       JOIN rooms_users ON rooms_users.room = rooms.id
       WHERE rooms.name = $1 AND rooms_users.user_id = $2`,
      [name, req.session.userId]
    )
    .then((resp) => {
      res.status(200).json(resp.rows);
    })
    .catch((err) => {
      console.log("err", err);
      res.status(500).json({ message: "Erro ao verificar sala" });
    });
};

// Chave de convite com 128 bits aleatórios (era o literal fixo "41421" no
// projeto original). Só é devolvida aqui, ao criador, que a repassa por fora
// do sistema a quem quiser convidar. O criador já entra na sala, na mesma
// transação da criação (sem isso, a sala nascia sem nenhum membro).
const createRooms = async (req, res) => {
  const name = req.body.name;
  const key = crypto.randomBytes(16).toString("hex");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query(
      "INSERT INTO rooms (name, key) VALUES ($1, $2) RETURNING id, name",
      [name, key]
    );
    await client.query(
      "INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)",
      [rows[0].id, req.session.userId]
    );
    await client.query("COMMIT");
    res.status(201).json({ id: rows[0].id, name: rows[0].name, key });
  } catch (err) {
    await client.query("ROLLBACK");
    console.log("err", err);
    res.status(500).json({ message: "Erro ao criar sala" });
  } finally {
    client.release();
  }
};

// Comparação em tempo constante. timingSafeEqual exige buffers do mesmo
// tamanho (e lança erro se não forem); comparar os SHA-256 das duas chaves
// resolve isso sem vazar, pelo tempo ou por exceção, o tamanho da chave real.
const sameKey = (provided, expected) => {
  if (typeof provided !== "string") return false;
  const digest = (value) => crypto.createHash("sha256").update(value, "utf8").digest();
  return crypto.timingSafeEqual(digest(provided), digest(expected));
};

// CORRIGIDO (item E): exige a chave de convite da sala. Sala inexistente e
// chave errada recebem a mesma resposta, para não revelar quais IDs existem.
const joinRooms = async (req, res) => {
  const roomId = req.body.idRoom;
  try {
    const { rows } = await pool.query("SELECT id, name, key FROM rooms WHERE id = $1", [roomId]);
    if (rows.length === 0 || !sameKey(req.body.key, rows[0].key)) {
      return res.status(403).json({ message: "Convite inválido" });
    }
    await pool.query(
      `INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)
       ON CONFLICT (room, user_id) DO NOTHING`,
      [roomId, req.session.userId]
    );
    return res.status(200).json({ id: rows[0].id, name: rows[0].name });
  } catch (err) {
    console.log("err", err);
    return res.status(500).json({ message: "Erro ao entrar na sala" });
  }
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

module.exports = { getRooms, createRooms, joinRooms, checkRoomExists, roomsUsers };
