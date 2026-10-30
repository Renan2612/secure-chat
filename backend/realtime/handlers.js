// Tratamento dos pacotes do cliente já autenticado (estado READY).
// A autorização é sempre consultada no banco (rooms_users), nunca em
// estado guardado na conexão: quem é removido da sala perde o acesso na hora.
const pool = require("../db");
const { parseEnvelope } = require("./envelope");
const { CLOCK_SKEW_SECONDS, systemClock, nowSeconds, expProblem } = require("../helpers/expiry");

const isMember = async (userId, room) =>
  (await pool.query("SELECT 1 FROM rooms_users WHERE room = $1 AND user_id = $2", [room, userId]))
    .rowCount > 0;

// Grava só se o remetente for membro, a sala não exigir rotação, o kv for a
// versão atual e o exp respeitar a retenção da sala, na MESMA consulta: não
// há janela entre checar e gravar. A linha da sala é lida com FOR SHARE: uma
// saída, remoção, rotação ou troca de retenção em andamento (FOR UPDATE)
// termina antes, e a condição é reavaliada sobre a linha nova. O remetente
// vem da sessão (conn.userId), nunca do pacote. Devolve { saved } (nova),
// { duplicate } (o cid já foi gravado nesta sala: reenvio), { reused } (cid
// já usado em outra sala), {} (não é membro da sala pedida), { rotation }
// (é membro, cid novo, mas a chave precisa ser trocada antes), { staleKey }
// (o kv do envelope não é a versão atual da chave da sala) ou { retention:
// código } (a sala tem retenção e o exp falta ou passa dela).
const insertIfMember = async (userId, room, cid, body, { kv, exp }, nowSec) => {
  const inserted = await pool.query(
    `INSERT INTO messages (room, user_id, message, cid, key_version, expires_at)
     SELECT r.id, $2, $3, $4, $5, to_timestamp($6::double precision) FROM rooms r
     WHERE r.id = $1 AND r.key_version = $5 AND NOT r.rotation_required
       AND (r.retention_seconds IS NULL OR $6::bigint <= $7::bigint + r.retention_seconds + $8::bigint)
       AND EXISTS (SELECT 1 FROM rooms_users WHERE room = $1 AND user_id = $2)
     FOR SHARE OF r
     ON CONFLICT (user_id, cid) DO NOTHING
     RETURNING id, dt_message`,
    [room, userId, body, cid, kv, exp, nowSec, CLOCK_SKEW_SECONDS]
  );
  if (inserted.rowCount > 0) return { saved: inserted.rows[0] };
  // Nada gravado. Autorização primeiro: quem não é membro da sala pedida
  // recebe NOT_MEMBER, haja ou não cid (e não descobre o estado da sala).
  if (!(await isMember(userId, room))) return {};
  // Reenvio: o body não é comparado (é opaco; um reenvio cifrado de novo tem
  // outro texto cifrado): vale o primeiro.
  const { rows } = await pool.query(
    "SELECT id, dt_message, room FROM messages WHERE user_id = $1 AND cid = $2",
    [userId, cid]
  );
  const original = rows[0];
  if (original) return original.room === room ? { duplicate: original } : { reused: true };
  // Membro, cid novo: faltou a rotação, a versão da chave ou a retenção.
  const state = (await pool.query("SELECT rotation_required, key_version, retention_seconds FROM rooms WHERE id = $1", [room])).rows[0];
  if (state?.rotation_required) return { rotation: true };
  if (state && state.key_version !== kv) return { staleKey: true };
  if (state?.retention_seconds !== null && state?.retention_seconds !== undefined) {
    return { retention: exp === null ? "RETENTION_REQUIRED" : "TTL_INVALID" };
  }
  return { staleKey: true };
};

// Usuários com o wrap da versão ATUAL da chave da sala (podem distribuí-la).
const keyHolders = async (room) => {
  const { rows } = await pool.query(
    "SELECT recipient_id FROM room_current_wraps WHERE room = $1",
    [room]
  );
  return new Set(rows.map((row) => row.recipient_id));
};

// Há membro sem o wrap da versão atual?
const hasPendingMembers = async (room) =>
  (
    await pool.query(
      `SELECT 1 FROM rooms_users m
       WHERE m.room = $1 AND NOT EXISTS (
         SELECT 1 FROM room_current_wraps w WHERE w.room = m.room AND w.recipient_id = m.user_id)
       LIMIT 1`,
      [room]
    )
  ).rowCount > 0;

const createHandlers = (registry, { clock = systemClock } = {}) => {
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

  // ROOM_EVENT (extensão do v1): só o aviso, sem dado de chave; o cliente
  // busca pela API HTTP (que confere a autorização de novo).
  // KEY_PENDING → inscritos na sala que têm a chave atual (os únicos que
  // podem entregar wraps). KEY_READY → todas as conexões do destinatário,
  // inscritas ou não (quem está sem chave pode nem ter feito SUBSCRIBE).
  const notifyKeyPending = async (room) => {
    const subscribers = registry.subscribers(room);
    if (subscribers.length === 0) return;
    const holders = await keyHolders(room);
    for (const conn of subscribers) {
      if (holders.has(conn.userId)) conn.send({ type: "ROOM_EVENT", room, kind: "KEY_PENDING" });
    }
  };

  const notifyKeyReady = (userId, room) => {
    for (const conn of registry.forUser(userId)) conn.send({ type: "ROOM_EVENT", room, kind: "KEY_READY" });
  };

  // Quem saiu ou foi removido: desinscrito da sala em todas as conexões (a
  // conexão continua aberta, para as outras salas) e avisado com REMOVED.
  const notifyRemoved = (userId, room) => {
    for (const conn of registry.forUser(userId)) {
      registry.unsubscribe(conn, room);
      conn.send({ type: "ROOM_EVENT", room, kind: "REMOVED" });
    }
  };

  // A chave precisa ser trocada (alguém saiu): todos os inscritos são
  // avisados; quem tem a chave atual pode rotacionar.
  const notifyRotationPending = (room) => {
    for (const conn of registry.subscribers(room)) conn.send({ type: "ROOM_EVENT", room, kind: "ROTATION_PENDING" });
  };

  // A chave foi trocada (nova versão): os inscritos buscam os próprios wraps.
  const notifyKeyRotated = (room) => {
    for (const conn of registry.subscribers(room)) conn.send({ type: "ROOM_EVENT", room, kind: "KEY_ROTATED" });
  };

  // Etapa 5: o dono mudou a retenção (vale para as mensagens futuras) ou o
  // nome cifrado da sala. A retenção não é segredo e vai no aviso; o nome
  // não: quem quiser busca o name_env em GET /rooms.
  const notifyRetentionChanged = (room, retentionSeconds) => {
    for (const conn of registry.subscribers(room)) conn.send({ type: "ROOM_EVENT", room, kind: "RETENTION_CHANGED", retentionSeconds });
  };

  // O dono mudou: aos inscritos e a TODAS as conexões do novo dono (ele
  // precisa re-assinar o nome mesmo sem estar inscrito na sala).
  const notifyOwnerChanged = (room, ownerId) => {
    const targets = new Set([...registry.subscribers(room), ...registry.forUser(ownerId)]);
    for (const conn of targets) conn.send({ type: "ROOM_EVENT", room, kind: "OWNER_CHANGED", ownerId });
  };

  const notifyRenamed = (room) => {
    for (const conn of registry.subscribers(room)) conn.send({ type: "ROOM_EVENT", room, kind: "RENAMED" });
  };

  const handlers = {
    // Sala inexistente e sala alheia recebem o mesmo NOT_MEMBER.
    async SUBSCRIBE(conn, { room, id }) {
      if (!(await isMember(conn.userId, room))) return conn.error("NOT_MEMBER", id);
      // A conexão pode ter fechado durante a consulta: não registrar inscrição
      // de conexão morta (o registry.remove do fechamento já rodou).
      if (!conn.isOpen()) return undefined;
      registry.subscribe(conn, room);
      conn.send({ type: "SUBSCRIBED", room });
      // Quem tem a chave e chega com membros pendentes já é avisado. É só um
      // aviso: se falhar, a inscrição (já confirmada) segue, sem ERROR.
      try {
        if ((await keyHolders(room)).has(conn.userId) && (await hasPendingMembers(room))) {
          conn.send({ type: "ROOM_EVENT", room, kind: "KEY_PENDING" });
        }
      } catch (err) {
        console.error(`[ws] falha ao verificar pendentes da sala ${room}: code=${err.code ?? "-"} ${err.message}`);
      }
      return undefined;
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
      // Falha fechada (E2EE): sem envelope cifrado v2 bem formado, nada é
      // gravado — impede mandar texto puro por engano. Só estrutura: o
      // servidor não decifra (não tem a chave da sala).
      const envelope = parseEnvelope(body);
      if (!envelope) return conn.error("E2EE_REQUIRED", id);
      // Limites do exp que não dependem da sala (não revelam nada dela).
      const nowSec = nowSeconds(clock);
      const ttl = expProblem(envelope.exp, nowSec);
      if (ttl) return conn.error(ttl, id);
      const { saved, duplicate, reused, rotation, staleKey, retention } = await insertIfMember(conn.userId, room, cid, body, envelope, nowSec);
      if (reused) return conn.error("CID_REUSED", id);
      if (rotation) return conn.error("ROTATION_PENDING", id);
      if (staleKey) return conn.error("KEY_VERSION_MISMATCH", id);
      if (retention) return conn.error(retention, id);
      const message = saved ?? duplicate;
      if (!message) return conn.error("NOT_MEMBER", id);
      const ts = message.dt_message.toISOString();
      conn.send({ type: "MSG_ACK", cid, id: message.id, ts });
      if (!saved) return undefined;
      // Vencida antes da entrega (o relógio andou durante a gravação): não
      // é entregue; o expurgo a apaga.
      if (envelope.exp !== null && envelope.exp * 1000 <= clock.nowMs()) return undefined;
      // A mensagem já está gravada e confirmada: uma falha na entrega não vira
      // ERROR para o remetente (seria ACK + ERROR para o mesmo envio). Os
      // inscritos a recuperam pelo histórico HTTP.
      try {
        // cid vai junto: o destinatário precisa dele para remontar o AAD e
        // para ignorar reentregas (mesmo remetente e cid).
        return await deliver(room, { type: "MSG_DELIVER", room, id: message.id, from: conn.userId, cid, ts, body });
      } catch (err) {
        console.error(`[ws] falha na entrega da mensagem ${message.id}: code=${err.code ?? "-"} ${err.message}`);
        return undefined;
      }
    },
  };

  return {
    handlers,
    notifyKeyPending,
    notifyKeyReady,
    notifyRemoved,
    notifyRotationPending,
    notifyKeyRotated,
    notifyRetentionChanged,
    notifyRenamed,
    notifyOwnerChanged,
  };
};

module.exports = { createHandlers };
