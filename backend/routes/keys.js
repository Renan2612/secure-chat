// Diretório de chaves PÚBLICAS da E2EE (docs/05-e2ee.md, D3). Sempre sobre o
// usuário da SESSÃO: nenhuma rota aceita userId no corpo. O servidor nunca
// recebe chave privada (o schema só tem ecdhPub/ecdsaPub e descarta o resto).
const pool = require("../db");
const { fingerprint } = require("../helpers/publicKeys");
const { withTransaction } = require("../helpers/transaction");

// Salas em que o usuário é membro mas não tem o wrap da versão atual: quem
// tem a chave nelas é avisado (ROOM_EVENT KEY_PENDING). Roda DEPOIS da
// gravação e sem segurar a resposta: uma falha aqui só perde o aviso (os
// clientes também descobrem pendentes ao se inscrever), nunca vira 500 de
// uma operação que já foi gravada.
const notifyPendingRooms = (req, userId) =>
  findPendingRooms(userId)
    .then((rooms) => rooms.forEach((room) => req.app.locals.notify.keyPending(room)))
    .catch((err) => console.error(`[keys] falha ao calcular avisos KEY_PENDING: code=${err.code ?? "-"} ${err.message}`));

const findPendingRooms = async (userId) => {
  const { rows } = await pool.query(
    `SELECT m.room FROM rooms_users m JOIN rooms r ON r.id = m.room
     WHERE m.user_id = $1 AND NOT EXISTS (
       SELECT 1 FROM room_current_wraps w WHERE w.room = r.id AND w.recipient_id = $1)`,
    [userId]
  );
  return rows.map((row) => row.room);
};

const toJson = (row, { withCreatedAt = true } = {}) => ({
  userId: row.user_id,
  ecdhPub: row.ecdh_pub,
  ecdsaPub: row.ecdsa_pub,
  fingerprint: row.fingerprint,
  keyEpoch: row.key_epoch,
  ...(withCreatedAt ? { createdAt: row.created_at.toISOString() } : {}),
});

const COLUMNS = "user_id, ecdh_pub, ecdsa_pub, fingerprint, key_epoch, created_at";

// Registra só se o usuário ainda não tem chave. A mesma chave de novo: 200
// (idempotente). Outra chave: 409 — trocar exige POST /keys/reset, que fica
// visível aos outros como chave alterada (key_epoch sobe).
const putKeys = async (req, res, next) => {
  const { ecdhPub, ecdsaPub } = req.body;
  try {
    const inserted = await pool.query(
      `INSERT INTO user_keys (user_id, ecdh_pub, ecdsa_pub, fingerprint) VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id) DO NOTHING RETURNING ${COLUMNS}`,
      [req.session.userId, ecdhPub, ecdsaPub, fingerprint({ ecdhPub, ecdsaPub })]
    );
    if (inserted.rowCount > 0) {
      // Com chave registrada, já dá para receber wraps nas salas em que entrou.
      notifyPendingRooms(req, req.session.userId);
      return res.status(201).json(toJson(inserted.rows[0]));
    }
    const { rows } = await pool.query(`SELECT ${COLUMNS} FROM user_keys WHERE user_id = $1`, [req.session.userId]);
    const current = rows[0];
    if (current && current.ecdh_pub === ecdhPub && current.ecdsa_pub === ecdsaPub) {
      return res.status(200).json(toJson(current));
    }
    return res.status(409).json({ message: "Chave já registrada; para trocar use POST /keys/reset" });
  } catch (err) {
    return next(err);
  }
};

// Substitui as chaves do PRÓPRIO usuário, incrementa key_epoch e apaga os
// wraps de que ele é DESTINATÁRIO (cifrados para a chave antiga, não servem
// mais): ele perde acesso às salas até alguém lhe entregar wraps novos. Os
// wraps que ele enviou a outros continuam valendo.
const resetKeys = async (req, res, next) => {
  const { ecdhPub, ecdsaPub } = req.body;
  const me = req.session.userId;
  try {
    const row = await withTransaction(async (client) => {
      const { rows } = await client.query(
        `UPDATE user_keys SET ecdh_pub = $2, ecdsa_pub = $3, fingerprint = $4, key_epoch = key_epoch + 1, created_at = NOW()
         WHERE user_id = $1 RETURNING ${COLUMNS}`,
        [me, ecdhPub, ecdsaPub, fingerprint({ ecdhPub, ecdsaPub })]
      );
      if (rows.length > 0) await client.query("DELETE FROM room_key_wraps WHERE recipient_id = $1", [me]);
      return rows[0];
    });
    if (!row) return res.status(404).json({ message: "Sem chave registrada; use PUT /keys" });
    notifyPendingRooms(req, me);
    return res.status(200).json(toJson(row));
  } catch (err) {
    return next(err);
  }
};

// Só para quem compartilha ao menos uma sala com o dono da chave (ou o
// próprio dono). Usuário sem sala em comum, inexistente ou sem chave: o
// mesmo 404, para o diretório não revelar quem existe.
const getKeys = async (req, res, next) => {
  const target = req.params.userId;
  const me = req.session.userId;
  try {
    const { rows } = await pool.query(
      `SELECT ${COLUMNS} FROM user_keys k
       WHERE k.user_id = $1
         AND ($1 = $2 OR EXISTS (
           SELECT 1 FROM rooms_users a JOIN rooms_users b ON a.room = b.room
           WHERE a.user_id = $2 AND b.user_id = $1))`,
      [target, me]
    );
    if (rows.length === 0) return res.status(404).json({ message: "Não encontrado" });
    return res.status(200).json(toJson(rows[0], { withCreatedAt: false }));
  } catch (err) {
    return next(err);
  }
};

module.exports = { putKeys, resetKeys, getKeys };
