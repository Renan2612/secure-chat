const pool = require("../db");

// Erros inesperados seguem para o error handler central (next), que
// responde 500 genérico e registra o erro sem dados da requisição.

// Histórico paginado (leitura). Pertencimento à sala verificado antes,
// pelo middleware requireRoomMember; limit/before validados pelo zod.
// Busca as `limit` mais recentes (antes de `before`, se informado) e as
// devolve em ordem cronológica. O envio é só pelo WebSocket (MSG_SEND).
const getMessages = async (req, res, next) => {
  const { limit, before } = req.query;
  try {
    const { rows } = await pool.query(
      `SELECT users.name AS userName, users.id AS userId, message AS message, dt_message AS dtMessage, messages.id as idMessage, rooms.name AS roomName, rooms.id as roomId FROM messages
    JOIN rooms
    ON room = rooms.id
    JOIN users
    ON users.id = messages.user_id
    WHERE rooms.id = $1 AND ($2::int IS NULL OR messages.id < $2)
    ORDER BY messages.id DESC
    LIMIT $3
    `,
      [req.params.id, before ?? null, limit]
    );
    return res.status(200).json(rows.reverse());
  } catch (err) {
    return next(err);
  }
};

const updateLastRead = async (req, res, next) => {
  try {
    await pool.query(
      `UPDATE rooms_users SET last_msg_viewed = $1 WHERE room = $2 AND user_id = $3`,
      [req.body.idLastMessage, req.body.room, req.session.userId]
    );
    return res.status(200).json({ message: "ok" });
  } catch (err) {
    return next(err);
  }
};

module.exports = { getMessages, updateLastRead };
