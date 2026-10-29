// Chave da sala (docs/05-e2ee.md, D4). O servidor guarda e entrega wraps;
// confere ESTRUTURA (zod), tamanhos e AUTORIZAÇÃO, nunca o conteúdo — ele
// não tem a chave privada de ninguém e não vê a chave da sala.
//
// Autorização, sempre com o usuário da SESSÃO:
//   publicar a versão 1  → criador da sala, membro, com chaves registradas
//   ler os próprios wraps → membro
//   ver pendentes        → membro que JÁ TEM o wrap da versão atual
//   descartar o próprio  → membro com wrap da versão atual (ex.: a chave não
//                          conferiu com o compromisso do criador)
//   publicar um wrap     → remetente membro com o wrap da versão atual;
//                          destinatário membro, com o key_epoch informado;
//                          um wrap por (sala, versão, destinatário)
const pool = require("../db");
const { withTransaction } = require("../helpers/transaction");

const FORBIDDEN = { message: "Acesso negado" };
const VERSION_MISMATCH = { message: "Versão da chave diferente da atual da sala" };

const roomState = async (roomId, userId) => {
  const { rows } = await pool.query(
    `SELECT r.id, r.created_by, r.key_version,
            EXISTS (SELECT 1 FROM rooms_users m WHERE m.room = r.id AND m.user_id = $2) AS member,
            EXISTS (SELECT 1 FROM room_current_wraps w WHERE w.room = r.id AND w.recipient_id = $2) AS has_key
     FROM rooms r WHERE r.id = $1`,
    [roomId, userId]
  );
  return rows[0];
};

const wrapRow = (w) => ({ version: w.version, senderId: w.sender_id, ephPub: w.eph_pub, iv: w.iv, wrapped: w.wrapped, sig: w.sig });

// O criador publica a versão 1 junto com o próprio wrap (uma transação).
const publishRoomKey = async (req, res, next) => {
  const roomId = req.params.id;
  const me = req.session.userId;
  const { version, wrap, commitment, commitmentSig } = req.body;
  try {
    const room = await roomState(roomId, me);
    // Sala inexistente, alheia ou de outro criador: o mesmo 403.
    if (!room || !room.member || room.created_by !== me) return res.status(403).json(FORBIDDEN);
    if (version !== room.key_version) return res.status(409).json(VERSION_MISMATCH);
    const hasKeys = (await pool.query("SELECT 1 FROM user_keys WHERE user_id = $1", [me])).rowCount > 0;
    if (!hasKeys) return res.status(409).json({ message: "Registre suas chaves públicas (PUT /keys) antes" });
    const published = await withTransaction(async (client) => {
      // FOR SHARE: um POST /keys/reset concorrente espera esta transação.
      const { rows: mine } = await client.query("SELECT key_epoch FROM user_keys WHERE user_id = $1 FOR SHARE", [me]);
      const inserted = await client.query(
        `INSERT INTO room_key_versions (room, version, created_by, commitment, commitment_sig) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT DO NOTHING RETURNING version`,
        [roomId, version, me, commitment, commitmentSig]
      );
      if (inserted.rowCount === 0) return false;
      await client.query(
        `INSERT INTO room_key_wraps (room, version, recipient_id, sender_id, recipient_key_epoch, eph_pub, iv, wrapped, sig)
         VALUES ($1, $2, $3, $3, $4, $5, $6, $7, $8)`,
        [roomId, version, me, mine[0].key_epoch, wrap.ephPub, wrap.iv, wrap.wrapped, wrap.sig]
      );
      return true;
    });
    if (!published) return res.status(409).json({ message: "Esta versão da chave já foi publicada" });
    return res.status(201).json({ room: roomId, version });
  } catch (err) {
    return next(err);
  }
};

// Só os wraps cujo destinatário é o próprio usuário, cifrados para a chave
// ATUAL dele (os de antes de um reset não abrem mais).
const getMyWraps = async (req, res, next) => {
  const roomId = req.params.id;
  try {
    const room = await roomState(roomId, req.session.userId);
    if (!room?.member) return res.status(403).json(FORBIDDEN);
    const { rows } = await pool.query(
      `SELECT w.version, w.sender_id, w.eph_pub, w.iv, w.wrapped, w.sig FROM room_key_wraps w
       JOIN user_keys k ON k.user_id = w.recipient_id AND k.key_epoch = w.recipient_key_epoch
       WHERE w.room = $1 AND w.recipient_id = $2 ORDER BY w.version`,
      [roomId, req.session.userId]
    );
    const versions = await pool.query(
      "SELECT version, created_by, commitment, commitment_sig FROM room_key_versions WHERE room = $1 ORDER BY version",
      [roomId]
    );
    return res.status(200).json({
      room: roomId,
      currentVersion: room.key_version,
      versions: versions.rows.map((v) => ({
        version: v.version,
        createdBy: v.created_by,
        commitment: v.commitment,
        commitmentSig: v.commitment_sig,
      })),
      wraps: rows.map(wrapRow),
    });
  } catch (err) {
    return next(err);
  }
};

// Membros sem wrap da versão atual, com as chaves públicas do diretório
// (null se ainda não registraram). O cliente CONFERE essas chaves contra o
// próprio trust store antes de embrulhar.
const getPending = async (req, res, next) => {
  const roomId = req.params.id;
  try {
    const room = await roomState(roomId, req.session.userId);
    if (!room?.member || !room.has_key) return res.status(403).json(FORBIDDEN);
    const { rows } = await pool.query(
      `SELECT u.id, u.name, k.ecdh_pub, k.ecdsa_pub, k.fingerprint, k.key_epoch
       FROM rooms_users m JOIN users u ON u.id = m.user_id
       LEFT JOIN user_keys k ON k.user_id = u.id
       WHERE m.room = $1 AND NOT EXISTS (
         SELECT 1 FROM room_current_wraps w WHERE w.room = $1 AND w.recipient_id = m.user_id)
       ORDER BY u.id`,
      [roomId]
    );
    const pending = rows.map((r) => ({
      userId: r.id,
      name: r.name,
      keys: r.ecdh_pub
        ? { ecdhPub: r.ecdh_pub, ecdsaPub: r.ecdsa_pub, fingerprint: r.fingerprint, keyEpoch: r.key_epoch }
        : null,
    }));
    return res.status(200).json({ room: roomId, version: room.key_version, pending });
  } catch (err) {
    return next(err);
  }
};

// A época da chave do destinatário é conferida e o wrap gravado na MESMA
// transação, com a linha dele em user_keys travada (FOR SHARE): um reset
// concorrente (UPDATE nessa linha) espera, e então apaga este wrap. Um wrap
// de época antiga que tenha ficado é substituído pelo novo, em vez de
// bloquear o destinatário com 409 para sempre.
const postWrap = async (req, res, next) => {
  const roomId = req.params.id;
  const me = req.session.userId;
  const { version, recipientId, recipientKeyEpoch, wrap } = req.body;
  try {
    const room = await roomState(roomId, me);
    if (!room?.member) return res.status(403).json(FORBIDDEN);
    if (version !== room.key_version) return res.status(409).json(VERSION_MISMATCH);
    if (!room.has_key) return res.status(403).json(FORBIDDEN);
    const isMember = (await pool.query("SELECT 1 FROM rooms_users WHERE room = $1 AND user_id = $2", [roomId, recipientId])).rowCount > 0;
    if (!isMember) return res.status(400).json({ message: "Destinatário inválido" });
    const outcome = await withTransaction(async (client) => {
      const { rows } = await client.query("SELECT key_epoch FROM user_keys WHERE user_id = $1 FOR SHARE", [recipientId]);
      if (rows[0]?.key_epoch !== recipientKeyEpoch) return "stale-recipient";
      const inserted = await client.query(
        `INSERT INTO room_key_wraps (room, version, recipient_id, sender_id, recipient_key_epoch, eph_pub, iv, wrapped, sig)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (room, version, recipient_id) DO UPDATE SET
           sender_id = EXCLUDED.sender_id, recipient_key_epoch = EXCLUDED.recipient_key_epoch,
           eph_pub = EXCLUDED.eph_pub, iv = EXCLUDED.iv, wrapped = EXCLUDED.wrapped, sig = EXCLUDED.sig, created_at = NOW()
         WHERE room_key_wraps.recipient_key_epoch < EXCLUDED.recipient_key_epoch
         RETURNING recipient_id`,
        [roomId, version, recipientId, me, recipientKeyEpoch, wrap.ephPub, wrap.iv, wrap.wrapped, wrap.sig]
      );
      return inserted.rowCount > 0 ? "saved" : "duplicate";
    });
    if (outcome === "stale-recipient") {
      return res.status(409).json({ message: "As chaves do destinatário mudaram; busque-as de novo" });
    }
    if (outcome === "duplicate") return res.status(409).json({ message: "Wrap já publicado para este destinatário" });
    req.app.locals.notify.keyReady(recipientId, roomId);
    return res.status(201).json({ room: roomId, version, recipientId });
  } catch (err) {
    return next(err);
  }
};

// O destinatário descarta o PRÓPRIO wrap da versão atual (a chave não
// conferiu com o compromisso: um membro lhe entregou uma chave falsa) e
// volta a ser pendente; quem tem a chave é avisado (KEY_PENDING).
const discardMyWrap = async (req, res, next) => {
  const roomId = req.params.id;
  const me = req.session.userId;
  try {
    const room = await roomState(roomId, me);
    if (!room?.member) return res.status(403).json(FORBIDDEN);
    const deleted = await pool.query(
      "DELETE FROM room_key_wraps WHERE room = $1 AND version = $2 AND recipient_id = $3",
      [roomId, room.key_version, me]
    );
    if (deleted.rowCount === 0) return res.status(404).json({ message: "Não encontrado" });
    req.app.locals.notify.keyPending(roomId);
    return res.status(204).send();
  } catch (err) {
    return next(err);
  }
};

module.exports = { publishRoomKey, getMyWraps, getPending, postWrap, discardMyWrap };
