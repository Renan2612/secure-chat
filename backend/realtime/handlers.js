// Tratamento dos pacotes do cliente já autenticado (estado READY).
// A autorização é sempre consultada no banco (rooms_users), nunca em
// estado guardado na conexão: quem é removido da sala perde o acesso na hora.
const pool = require("../db");

const isMember = async (userId, room) =>
  (await pool.query("SELECT 1 FROM rooms_users WHERE room = $1 AND user_id = $2", [room, userId]))
    .rowCount > 0;

const createHandlers = (registry) => ({
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
});

module.exports = { createHandlers, isMember };
