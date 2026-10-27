const pool = require("../db");

// Erros inesperados seguem para o error handler central (next), que
// responde 500 genérico e registra o erro sem dados da requisição.

// Pertencimento à sala verificado antes, pelo middleware requireRoomMember.
// CORRIGIDO: não grava mais req.session.room (estado desnecessário na sessão).
const getMessages = async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT users.name AS userName, users.id AS userId, message AS message, dt_message AS dtMessage, messages.id as idMessage, rooms.name AS roomName, rooms.id as roomId FROM messages
    JOIN rooms
    ON room = rooms.id
    JOIN users
    ON users.id = messages.user_id
    WHERE rooms.id = $1
    ;
    `,
      [req.params.id]
    );
    return res.status(200).json(rows);
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

// CORRIGIDO (item C): o remetente é SEMPRE o usuário da sessão. Qualquer
// "user"/"user_id" enviado pelo cliente no corpo é ignorado — antes, o
// servidor gravava message.user.id do corpo e qualquer um forjava o autor.
// Que a sala existe e que o usuário é membro já foi garantido pelo
// middleware requireRoomMember (pertencer a rooms_users implica a sala
// existir, pela chave estrangeira).
const postMessages = async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `INSERT INTO messages (room, user_id, message, dt_message) VALUES ($1, $2, $3, $4)
       RETURNING id, room, user_id, message, dt_message`,
      [req.body.room, req.session.userId, req.body.message, new Date().toUTCString()]
    );
    return res.status(201).json(rows[0]);
  } catch (err) {
    return next(err);
  }
};

module.exports = { getMessages, postMessages, updateLastRead };
