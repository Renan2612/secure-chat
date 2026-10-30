// Ajustes da sala que só o DONO faz (Etapa 5): retenção das mensagens (A1),
// nome cifrado (A3) e banimentos (A2). Mesmo padrão de routes/members.js:
// transação com a linha da sala travada (FOR UPDATE) e respostas genéricas
// (sala inexistente ou alheia: 404; membro que não é o dono: 403; alvo que
// não está banido: o mesmo 404).
const { withTransaction } = require("../helpers/transaction");
const { parseRoomNameEnvelope } = require("../helpers/roomName");
const { NOT_FOUND, lockOwnedRoom } = require("./members");

const reply = async (res, next, run, onOk) => {
  try {
    const outcome = await withTransaction(run);
    if (!outcome.ok) return res.status(outcome.status).json(outcome.body);
    return onOk(outcome);
  } catch (err) {
    return next(err);
  }
};

// PUT /rooms/:id/retention { retentionSeconds: 60..604800 | null }. Vale
// para as mensagens FUTURAS (as já gravadas mantêm o exp que o remetente
// assinou): com retenção, todo MSG_SEND precisa de exp <= agora + retenção.
// O MSG_SEND lê a sala com FOR SHARE: o que chegar depois desta transação
// já segue a regra nova.
const setRetention = (req, res, next) => {
  const roomId = req.params.id;
  const { retentionSeconds } = req.body;
  return reply(
    res,
    next,
    async (client) => {
      const refused = await lockOwnedRoom(client, roomId, req.session.userId);
      if (refused) return refused;
      await client.query("UPDATE rooms SET retention_seconds = $2 WHERE id = $1", [roomId, retentionSeconds]);
      return { ok: true };
    },
    () => {
      req.app.locals.notify.retentionChanged(roomId, retentionSeconds);
      return res.status(200).json({ room: roomId, retentionSeconds });
    }
  );
};

// PUT /rooms/:id/name { nameEnv }: o nome cifrado com a chave ATUAL (kv =
// key_version), por um dono que tem essa chave (room_current_wraps). O
// servidor só confere a estrutura e o kv.
const setName = (req, res, next) => {
  const roomId = req.params.id;
  const me = req.session.userId;
  const { nameEnv } = req.body;
  return reply(
    res,
    next,
    async (client) => {
      const refused = await lockOwnedRoom(client, roomId, me);
      if (refused) return refused;
      const { rows } = await client.query(
        `SELECT r.key_version, r.rotation_required,
                EXISTS (SELECT 1 FROM room_current_wraps w WHERE w.room = r.id AND w.recipient_id = $2) AS has_key
         FROM rooms r WHERE r.id = $1`,
        [roomId, me]
      );
      const room = rows[0];
      if (!room.has_key) return { status: 403, body: { message: "Acesso negado" } };
      // Com a rotação pendente, quem saiu ainda tem a chave atual: o nome
      // novo só vai na rotação, recifrado com a chave nova.
      if (room.rotation_required) {
        return { status: 409, body: { code: "ROTATION_PENDING", message: "A chave da sala precisa ser trocada antes" } };
      }
      if (parseRoomNameEnvelope(nameEnv).kv !== room.key_version) {
        return { status: 409, body: { message: "Versão da chave diferente da atual da sala" } };
      }
      await client.query("UPDATE rooms SET name_env = $2 WHERE id = $1", [roomId, nameEnv]);
      return { ok: true };
    },
    () => {
      req.app.locals.notify.renamed(roomId);
      return res.status(200).json({ room: roomId });
    }
  );
};

// GET /rooms/:id/bans: quem o dono removeu (e que não volta com convite).
const listBans = (req, res, next) =>
  reply(
    res,
    next,
    async (client) => {
      const refused = await lockOwnedRoom(client, req.params.id, req.session.userId);
      if (refused) return refused;
      const { rows } = await client.query(
        `SELECT b.user_id, u.name FROM room_bans b JOIN users u ON u.id = b.user_id
         WHERE b.room = $1 ORDER BY b.user_id`,
        [req.params.id]
      );
      return { ok: true, bans: rows.map((r) => ({ userId: r.user_id, name: r.name })) };
    },
    (outcome) => res.status(200).json({ room: req.params.id, bans: outcome.bans })
  );

// DELETE /rooms/:id/bans/:userId: desfaz o banimento. NÃO devolve o vínculo
// nem a chave: a pessoa precisa de um convite válido (o de antes da remoção
// já foi trocado) e de alguém que lhe entregue a chave atual.
const unban = (req, res, next) =>
  reply(
    res,
    next,
    async (client) => {
      const refused = await lockOwnedRoom(client, req.params.id, req.session.userId);
      if (refused) return refused;
      const deleted = await client.query("DELETE FROM room_bans WHERE room = $1 AND user_id = $2", [
        req.params.id,
        req.params.userId,
      ]);
      return deleted.rowCount > 0 ? { ok: true } : NOT_FOUND;
    },
    () => res.status(204).send()
  );

module.exports = { setRetention, setName, listBans, unban };
