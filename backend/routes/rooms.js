const crypto = require("crypto");
const pool = require("../db");

// Erros inesperados seguem para o error handler central (next), que
// responde 500 genérico e registra o erro sem dados da requisição.

const getRooms = async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT distinct rooms.id, rooms.name,  (SELECT COUNT(*) FROM messages WHERE room = rooms.id AND id > rooms_users.last_msg_viewed) as nummessages FROM rooms
    JOIN rooms_users
    ON rooms.id = rooms_users.room
    WHERE rooms_users.user_id = $1
    `,
      [req.session.userId]
    );
    return res.status(200).json(rows);
  } catch (err) {
    return next(err);
  }
};

// Busca só entre as salas das quais o usuário já é membro (uso: avisar que
// ele já tem uma sala com esse nome). CORRIGIDO: antes buscava em TODAS as
// salas e revelava nome e ID de salas privadas de terceiros.
const checkRoomExists = async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT rooms.id, rooms.name FROM rooms
       JOIN rooms_users ON rooms_users.room = rooms.id
       WHERE rooms.name = $1 AND rooms_users.user_id = $2`,
      [req.body.name, req.session.userId]
    );
    return res.status(200).json(rows);
  } catch (err) {
    return next(err);
  }
};

// Chave de convite com 128 bits aleatórios (era o literal fixo "41421" no
// projeto original). Só é devolvida aqui, ao criador, que a repassa por fora
// do sistema a quem quiser convidar; o banco guarda só o SHA-256 (D5 da 4b-2). O criador já entra na sala, na mesma
// transação da criação (sem isso, a sala nascia sem nenhum membro).
const createRooms = async (req, res, next) => {
  const key = crypto.randomBytes(16).toString("hex");
  let client;
  let brokenConnection;
  // Um client retirado do pool não tem listener de 'error'; se a conexão
  // cair no meio da transação, o pg emite 'error' e, sem listener, o Node
  // derruba o PROCESSO inteiro. O listener marca a conexão como quebrada
  // (a query pendente também rejeita e cai no catch abaixo).
  const onConnectionError = (connErr) => {
    brokenConnection = connErr;
  };
  try {
    client = await pool.connect();
    client.on("error", onConnectionError);
    await client.query("BEGIN");
    const { rows } = await client.query(
      "INSERT INTO rooms (name, invite_hash, created_by, owner_id) VALUES ($1, $2, $3, $3) RETURNING id, name",
      [req.body.name, inviteHash(key), req.session.userId]
    );
    await client.query(
      "INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)",
      [rows[0].id, req.session.userId]
    );
    await client.query("COMMIT");
    return res.status(201).json({ id: rows[0].id, name: rows[0].name, key });
  } catch (err) {
    // Se o ROLLBACK também falhar, a conexão está quebrada: release(erro)
    // a descarta em vez de devolvê-la ao pool. O erro reportado é o original.
    if (client && !brokenConnection) {
      await client.query("ROLLBACK").catch((rollbackErr) => {
        console.error("[erro] ROLLBACK falhou em createRooms:", rollbackErr.message);
        brokenConnection = rollbackErr;
      });
    }
    return next(err);
  } finally {
    if (client) {
      client.removeListener("error", onConnectionError);
      client.release(brokenConnection);
    }
  }
};

const inviteHash = (invite) => crypto.createHash("sha256").update(invite, "utf8").digest("hex");

// Comparação em tempo constante dos SHA-256 (o convite em si não está no
// banco). Os dois lados têm 32 bytes, então timingSafeEqual não lança nem
// vaza, pelo tempo, o tamanho do convite real.
const sameInvite = (provided, storedHash) => {
  if (typeof provided !== "string") return false;
  return crypto.timingSafeEqual(Buffer.from(inviteHash(provided), "hex"), Buffer.from(storedHash, "hex"));
};

// CORRIGIDO (item E): exige a chave de convite da sala. Sala inexistente e
// chave errada recebem a mesma resposta, para não revelar quais IDs existem.
const joinRooms = async (req, res, next) => {
  const roomId = req.body.idRoom;
  try {
    const { rows } = await pool.query("SELECT id, name, invite_hash FROM rooms WHERE id = $1", [roomId]);
    if (rows.length === 0 || !sameInvite(req.body.key, rows[0].invite_hash)) {
      return res.status(403).json({ message: "Convite inválido" });
    }
    const joined = await pool.query(
      `INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)
       ON CONFLICT (room, user_id) DO NOTHING`,
      [roomId, req.session.userId]
    );
    // Novo membro entra "sem chave": avisa quem pode lhe entregar um wrap.
    if (joined.rowCount > 0) req.app.locals.notify.keyPending(roomId);
    return res.status(200).json({ id: rows[0].id, name: rows[0].name });
  } catch (err) {
    return next(err);
  }
};

// Pertencimento à sala verificado antes, pelo middleware requireRoomMember.
const roomsUsers = async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT users.name, users.id
      FROM rooms_users
      JOIN users
      ON user_id = users.id
      WHERE room = $1;
    `,
      [req.params.room]
    );
    return res.status(200).json(rows);
  } catch (err) {
    return next(err);
  }
};

module.exports = { inviteHash, getRooms, createRooms, joinRooms, checkRoomExists, roomsUsers };
