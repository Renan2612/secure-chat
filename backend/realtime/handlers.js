// Tratamento dos pacotes do cliente já autenticado (estado READY).
// A autorização é sempre consultada no banco (rooms_users), nunca em
// estado guardado na conexão: quem é removido da sala perde o acesso na hora.
const pool = require("../db");

const isMember = async (userId, room) =>
  (await pool.query("SELECT 1 FROM rooms_users WHERE room = $1 AND user_id = $2", [room, userId]))
    .rowCount > 0;

// Grava só se o remetente for membro, na MESMA consulta: não há janela entre
// checar a pertinência e gravar. O remetente vem da sessão (conn.userId),
// nunca do pacote. Devolve { saved } (nova), { duplicate } (o cid já foi
// gravado nesta sala: reenvio) ou {} (não é membro, ou cid de outra sala).
const insertIfMember = async (userId, room, cid, body) => {
  const inserted = await pool.query(
    `INSERT INTO messages (room, user_id, message, cid)
     SELECT $1, $2, $3, $4
     WHERE EXISTS (SELECT 1 FROM rooms_users WHERE room = $1 AND user_id = $2)
     ON CONFLICT (user_id, cid) DO NOTHING
     RETURNING id, dt_message`,
    [room, userId, body, cid]
  );
  if (inserted.rowCount > 0) return { saved: inserted.rows[0] };
  // Reenvio: só é reconhecido para quem continua membro da sala. O body do
  // reenvio não é comparado (é opaco; na Etapa 4 um reenvio cifrado de novo
  // terá outro texto cifrado): vale o primeiro.
  const existing = await pool.query(
    `SELECT m.id, m.dt_message, m.room FROM messages m
     JOIN rooms_users ru ON ru.room = m.room AND ru.user_id = m.user_id
     WHERE m.user_id = $1 AND m.cid = $2`,
    [userId, cid]
  );
  const original = existing.rows[0];
  if (!original) return {};
  return original.room === room ? { duplicate: original } : { reused: true };
};

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
    // Reenvio do mesmo cid: devolve o MSG_ACK original, sem gravar nem
    // entregar de novo.
    async MSG_SEND(conn, { room, cid, body, id }) {
      const { saved, duplicate, reused } = await insertIfMember(conn.userId, room, cid, body);
      if (reused) return conn.error("CID_REUSED", id);
      const message = saved ?? duplicate;
      if (!message) return conn.error("NOT_MEMBER", id);
      const ts = message.dt_message.toISOString();
      conn.send({ type: "MSG_ACK", cid, id: message.id, ts });
      if (!saved) return undefined;
      // A mensagem já está gravada e confirmada: uma falha na entrega não vira
      // ERROR para o remetente (seria ACK + ERROR para o mesmo envio). Os
      // inscritos a recuperam pelo histórico HTTP.
      try {
        return await deliver(room, { type: "MSG_DELIVER", room, id: message.id, from: conn.userId, ts, body });
      } catch (err) {
        console.error(`[ws] falha na entrega da mensagem ${message.id}: code=${err.code ?? "-"} ${err.message}`);
        return undefined;
      }
    },
  };
};

module.exports = { createHandlers, isMember };
