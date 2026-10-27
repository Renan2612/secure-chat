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

// ATENÇÃO (Etapa 2): o remetente (message.user.id) vem do corpo da
// requisição, ou seja, do CLIENTE — e não da sessão autenticada no servidor.
// Isso permite forjar mensagens em nome de outro usuário. O servidor deve
// usar req.session.userId como remetente, nunca o que o cliente envia.
// Mantido assim de propósito para servir de linha de base de comparação.
const postMessages = (req, res) => {
  const today = new Date(Date.now());
  const message = req.body;
  const data = today.toUTCString();

  pool
    .query(
      `INSERT INTO messages (room, user_id, message, dt_message) VALUES ($1, $2, $3 , $4) returning *;
    `,
      [message.room.id, message.user.id, message.message, data]
    )
    .then((result) => result.rows)
    .then((messages) => {
      res.status(201).json(messages);
    })
    .catch((err) => {
      console.log("err", err);
      res.status(400).json({ message: "Erro ao enviar mensagem" });
    });
};

module.exports = { getMessages, postMessages, updateLastRead };
