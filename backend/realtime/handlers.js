// Tratamento dos pacotes do cliente já autenticado (estado READY).
// A autorização é sempre consultada no banco (rooms_users), nunca em
// estado guardado na conexão: quem é removido da sala perde o acesso na hora.
const pool = require("../db");

const isMember = async (userId, room) =>
  (await pool.query("SELECT 1 FROM rooms_users WHERE room = $1 AND user_id = $2", [room, userId]))
    .rowCount > 0;

// Grava só se o remetente for membro, na MESMA consulta: não há janela entre
// checar a pertinência e gravar. Nenhuma linha → não é membro (ou a sala não
// existe). O remetente vem da sessão (conn.userId), nunca do pacote.
const insertIfMember = async (userId, room, body) =>
  (
    await pool.query(
      `INSERT INTO messages (room, user_id, message)
       SELECT $1, $2, $3
       WHERE EXISTS (SELECT 1 FROM rooms_users WHERE room = $1 AND user_id = $2)
       RETURNING id, dt_message`,
      [room, userId, body]
    )
  ).rows[0];

const createHandlers = (registry) => {
  // Entrega só às conexões inscritas na sala cujo usuário AINDA é membro;
  // inscrições de quem saiu da sala são desfeitas aqui (UNSUBSCRIBED).
  const deliver = async (room, packet) => {
    const subscribers = registry.subscribers(room);
    if (subscribers.length === 0) return;
    const { rows } = await pool.query("SELECT user_id FROM rooms_users WHERE room = $1", [room]);
    const members = new Set(rows.map((row) => row.user_id));
    for (const conn of subscribers) {
      if (members.has(conn.userId)) {
        conn.send(packet);
      } else {
        registry.unsubscribe(conn, room);
        conn.send({ type: "UNSUBSCRIBED", room });
      }
    }
  };

  return {
    // Sala inexistente e sala alheia recebem o mesmo NOT_MEMBER.
    async SUBSCRIBE(conn, { room, id }) {
      if (!(await isMember(conn.userId, room))) return conn.error("NOT_MEMBER", id);
      // A conexão pode ter fechado durante a consulta: não registrar inscrição
      // de conexão morta (o registry.remove do fechamento já rodou).
      if (!conn.isOpen()) return undefined;
      registry.subscribe(conn, room);
      return conn.send({ type: "SUBSCRIBED", room });
    },

    async UNSUBSCRIBE(conn, { room }) {
      registry.unsubscribe(conn, room);
      return conn.send({ type: "UNSUBSCRIBED", room });
    },

    // Grava no Postgres e só então confirma (MSG_ACK) e entrega (MSG_DELIVER).
    // O body é opaco: repassado como veio, nunca interpretado nem logado.
    async MSG_SEND(conn, { room, cid, body, id }) {
      const saved = await insertIfMember(conn.userId, room, body);
      if (!saved) return conn.error("NOT_MEMBER", id);
      const ts = saved.dt_message.toISOString();
      conn.send({ type: "MSG_ACK", cid, id: saved.id, ts });
      return deliver(room, { type: "MSG_DELIVER", room, id: saved.id, from: conn.userId, ts, body });
    },
  };
};

module.exports = { createHandlers, isMember };
