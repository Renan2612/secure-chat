const crypto = require("crypto");
const pool = require("../db");
const { withTransaction } = require("../helpers/transaction");

// Erros inesperados seguem para o error handler central (next), que
// responde 500 genérico e registra o erro sem dados da requisição.

// Etapa 5: o nome da sala só existe cifrado (nameEnv, A3); sem a chave o
// cliente mostra "Sala #id". nummessages não conta as já vencidas.
const getRooms = async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT rooms.id, rooms.name_env, rooms.retention_seconds, rooms.owner_id,
              (SELECT COUNT(*) FROM messages
                WHERE room = rooms.id AND id > rooms_users.last_msg_viewed
                  AND (expires_at IS NULL OR expires_at > to_timestamp($2::double precision))) AS nummessages
       FROM rooms JOIN rooms_users ON rooms.id = rooms_users.room
       WHERE rooms_users.user_id = $1
       ORDER BY rooms.id`,
      [req.session.userId, req.app.locals.clock.nowMs() / 1000]
    );
    return res.status(200).json(
      rows.map((r) => ({
        id: r.id,
        nameEnv: r.name_env,
        retentionSeconds: r.retention_seconds,
        ownerId: r.owner_id,
        nummessages: r.nummessages,
      }))
    );
  } catch (err) {
    return next(err);
  }
};

// A busca por nome (POST /checkRoomExists) foi REMOVIDA na Etapa 5: o
// servidor não conhece mais o nome das salas (A3).

// Chave de convite com 128 bits aleatórios (era o literal fixo "41421" no
// projeto original). Só é devolvida aqui, ao criador, que a repassa por fora
// do sistema a quem quiser convidar; o banco guarda só o SHA-256 (D5 da 4b-2).
// O criador já entra na sala, na mesma transação da criação (sem isso, a
// sala nascia sem nenhum membro). Sem nome: ele chega cifrado, junto com a
// publicação da v1 da chave (POST /rooms/:id/keys), porque o AAD do nome
// precisa do id da sala.
const createRooms = async (req, res, next) => {
  const key = crypto.randomBytes(16).toString("hex");
  let client;
  let brokenConnection;
  // Um client retirado do pool não tem listener de 'error'; se a conexão
  // cair no meio da transação, o pg emite 'error' e, sem listener, o Node
  // derruba o PROCESSO inteiro. O listener marca a conexão como quebrada
  // (a query pendente também rejeita e cai no catch abaixo).
  const onConnectionError = (connErr) => {
    brokenConnection = connErr;
  };
  try {
    client = await pool.connect();
    client.on("error", onConnectionError);
    await client.query("BEGIN");
    const { rows } = await client.query(
      "INSERT INTO rooms (invite_hash, created_by, owner_id) VALUES ($1, $2, $2) RETURNING id",
      [inviteHash(key), req.session.userId]
    );
    await client.query(
      "INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)",
      [rows[0].id, req.session.userId]
    );
    await client.query("COMMIT");
    return res.status(201).json({ id: rows[0].id, key });
  } catch (err) {
    // Se o ROLLBACK também falhar, a conexão está quebrada: release(erro)
    // a descarta em vez de devolvê-la ao pool. O erro reportado é o original.
    if (client && !brokenConnection) {
      await client.query("ROLLBACK").catch((rollbackErr) => {
        console.error("[erro] ROLLBACK falhou em createRooms:", rollbackErr.message);
        brokenConnection = rollbackErr;
      });
    }
    return next(err);
  } finally {
    if (client) {
      client.removeListener("error", onConnectionError);
      client.release(brokenConnection);
    }
  }
};

const inviteHash = (invite) => crypto.createHash("sha256").update(invite, "utf8").digest("hex");

// Comparação em tempo constante dos SHA-256 (o convite em si não está no
// banco). Os dois lados têm 32 bytes, então timingSafeEqual não lança nem
// vaza, pelo tempo, o tamanho do convite real.
const sameInvite = (provided, storedHash) => {
  if (typeof provided !== "string") return false;
  return crypto.timingSafeEqual(Buffer.from(inviteHash(provided), "hex"), Buffer.from(storedHash, "hex"));
};

// CORRIGIDO (item E): exige a chave de convite da sala. Sala inexistente,
// chave errada e usuário banido (removido pelo dono, room_bans) recebem a
// mesma resposta, para não revelar quais IDs existem nem quem foi banido.
// FOR SHARE na sala: uma remoção (que troca o convite e bane) ou a exclusão
// da sala em andamento termina antes desta entrada ser avaliada.
const joinRooms = async (req, res, next) => {
  const roomId = req.body.idRoom;
  const me = req.session.userId;
  try {
    const outcome = await withTransaction(async (client) => {
      const { rows } = await client.query(
        `SELECT r.id, r.invite_hash,
                EXISTS (SELECT 1 FROM room_bans b WHERE b.room = r.id AND b.user_id = $2) AS banned
         FROM rooms r WHERE r.id = $1 FOR SHARE`,
        [roomId, me]
      );
      const room = rows[0];
      if (!room || !sameInvite(req.body.key, room.invite_hash) || room.banned) return null;
      const joined = await client.query(
        `INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)
         ON CONFLICT (room, user_id) DO NOTHING`,
        [roomId, me]
      );
      return { room, joined: joined.rowCount > 0 };
    });
    if (!outcome) return res.status(403).json({ message: "Convite inválido" });
    // Novo membro entra "sem chave": avisa quem pode lhe entregar um wrap.
    if (outcome.joined) req.app.locals.notify.keyPending(roomId);
    return res.status(200).json({ id: outcome.room.id });
  } catch (err) {
    return next(err);
  }
};

// Pertencimento à sala verificado antes, pelo middleware requireRoomMember.
const roomsUsers = async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT users.name, users.id
      FROM rooms_users
      JOIN users
      ON user_id = users.id
      WHERE room = $1;
    `,
      [req.params.room]
    );
    return res.status(200).json(rows);
  } catch (err) {
    return next(err);
  }
};

module.exports = { inviteHash, getRooms, createRooms, joinRooms, roomsUsers };
