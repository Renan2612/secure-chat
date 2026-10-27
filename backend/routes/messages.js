const pool = require("../db");

// Pertencimento à sala verificado antes, pelo middleware requireRoomMember.
// CORRIGIDO: não grava mais req.session.room (estado desnecessário na sessão).
const getMessages = (req, res) => {
  const room = req.params.id;
  pool
    .query(
      `SELECT users.name AS userName, users.id AS userId, message AS message, dt_message AS dtMessage, messages.id as idMessage, rooms.name AS roomName, rooms.id as roomId FROM messages
    JOIN rooms
    ON room = rooms.id
    JOIN users
    ON users.id = messages.user_id
    WHERE rooms.id = $1
    ;
    `,
      [room]
    )
    .then((result) => result.rows)
    .then((messages) => {
      res.status(200).json(messages);
    })
    .catch((err) => {
      console.log("err", err);
      res.status(500).json({ message: "Erro ao buscar mensagens" });
    });
};

const updateLastRead = (req, res) => {
  const room = req.body.room;
  const userId = req.session.userId;
  const idLastMessage = req.body.idLastMessage;
  pool
    .query(
      `UPDATE rooms_users SET last_msg_viewed = $1 WHERE room = $2 AND user_id = $3`,
      [idLastMessage, room, userId]
    )
    .then(() => {
      res.status(200).json({ message: "ok" });
    })
    .catch((err) => {
      console.log("error", err);
      res.status(500).json({ message: "Erro ao atualizar leitura" });
    });
};

// CORRIGIDO (item C): o remetente é SEMPRE o usuário da sessão. Qualquer
// "user"/"user_id" enviado pelo cliente no corpo é ignorado — antes, o
// servidor gravava message.user.id do corpo e qualquer um forjava o autor.
// Que a sala existe e que o usuário é membro já foi garantido pelo
// middleware requireRoomMember (pertencer a rooms_users implica a sala
// existir, pela chave estrangeira).
const postMessages = (req, res) => {
  const today = new Date(Date.now());
  const data = today.toUTCString();

  pool
    .query(
      `INSERT INTO messages (room, user_id, message, dt_message) VALUES ($1, $2, $3 , $4)
       RETURNING id, room, user_id, message, dt_message;
    `,
      [req.body.room, req.session.userId, req.body.message, data]
    )
    .then((result) => {
      res.status(201).json(result.rows[0]);
    })
    .catch((err) => {
      console.log("err", err);
      res.status(400).json({ message: "Erro ao enviar mensagem" });
    });
};

module.exports = { getMessages, postMessages, updateLastRead };
