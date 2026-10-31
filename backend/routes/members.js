// Ciclo de vida dos membros (Etapa 4b-2, D1 e D2): sair, remover e
// transferir o cargo de dono. Tudo numa transação com a linha da sala
// travada (FOR UPDATE): saídas, remoções, transferências e rotações da mesma
// sala acontecem uma de cada vez, e o MSG_SEND (que confere a sala na mesma
// consulta que grava) espera a remoção terminar.
//
// Quem sai ou é removido perde o vínculo e TODOS os wraps da sala (nenhuma
// versão da chave lhe é entregue de novo) e a sala passa a exigir rotação
// (rotation_required): até um membro trocar a chave, nada é enviado.
// Remover também bane (room_bans) e troca o convite.
//
// Sala inexistente, sala alheia e alvo que não é membro recebem a mesma
// resposta genérica (404), para não revelar quais salas e membros existem.
const crypto = require("crypto");
const { withTransaction } = require("../helpers/transaction");
const { inviteHash } = require("./rooms");

// Recusas: as transações devolvem { status, body } pronto (sempre antes de
// qualquer gravação) ou { ok: true, ... } quando gravam; a resposta só é
// enviada depois do fim da transação.
const NOT_FOUND = { status: 404, body: { message: "Sala ou membro inexistente" } };
const FORBIDDEN = { status: 403, body: { message: "Acesso negado" } };
const refuse = (status, message) => ({ status, body: { message } });

// SÓ PARA A MUTAÇÃO DO scripts/verify-e2ee.sh (MUTATION=server-no-rotation):
// com este valor exato, o servidor deixa de exigir a rotação depois de uma
// saída ou remoção (quebra a E2EE de propósito, para provar que o script
// percebe). Nunca está ativa por padrão; o backend avisa no log ao subir.
const { honored } = require("../config/testFlags");
const SKIP_ROTATION_VALUE = "inseguro-so-para-teste";
// Só tem efeito em NODE_ENV=test (config/testFlags.js).
const skipRotationForTest = () => honored("E2EE_TEST_SKIP_ROTATION", SKIP_ROTATION_VALUE);

const newInvite = () => crypto.randomBytes(16).toString("hex");

// Linha da sala travada, com o papel de quem pede. undefined se a sala não
// existe ou se o usuário não é membro dela.
const lockRoomFor = async (client, roomId, userId) => {
  const { rows } = await client.query(
    `SELECT r.id, r.owner_id FROM rooms r
     WHERE r.id = $1 AND EXISTS (SELECT 1 FROM rooms_users m WHERE m.room = r.id AND m.user_id = $2)
     FOR UPDATE OF r`,
    [roomId, userId]
  );
  return rows[0];
};

// Trava a sala e confere que quem pede é o dono: devolve a recusa (404 antes
// de 403, para não revelar a sala a quem não é membro) ou undefined.
const lockOwnedRoom = async (client, roomId, userId) => {
  const room = await lockRoomFor(client, roomId, userId);
  if (!room) return NOT_FOUND;
  if (room.owner_id !== userId) return FORBIDDEN;
  return undefined;
};

const setInvite = (client, roomId, invite) =>
  client.query("UPDATE rooms SET invite_hash = $2 WHERE id = $1", [roomId, inviteHash(invite)]);

// Tira o usuário da sala: vínculo e todos os wraps em que ele é destinatário.
// Se ninguém ficar, apaga a sala (cascata: mensagens, versões, wraps, bans);
// senão, marca a rotação como exigida. Devolve true se a sala foi apagada.
const detach = async (client, roomId, userId) => {
  await client.query("DELETE FROM room_key_wraps WHERE room = $1 AND recipient_id = $2", [roomId, userId]);
  await client.query("DELETE FROM rooms_users WHERE room = $1 AND user_id = $2", [roomId, userId]);
  const left = await client.query("SELECT 1 FROM rooms_users WHERE room = $1 LIMIT 1", [roomId]);
  if (left.rowCount === 0) {
    await client.query("DELETE FROM rooms WHERE id = $1", [roomId]);
    return true;
  }
  if (!skipRotationForTest()) await client.query("UPDATE rooms SET rotation_required = TRUE WHERE id = $1", [roomId]);
  return false;
};

// Avisos depois do COMMIT: o usuário que saiu é desinscrito da sala em todas
// as conexões (sem fechá-las) e recebe REMOVED; os inscritos que ficaram,
// ROTATION_PENDING.
const announce = (req, roomId, userId, roomDeleted) => {
  req.app.locals.notify.removed(userId, roomId);
  if (!roomDeleted && !skipRotationForTest()) req.app.locals.notify.rotationPending(roomId);
};

const leaveRoom = async (req, res, next) => {
  const roomId = req.params.id;
  const me = req.session.userId;
  try {
    const outcome = await withTransaction(async (client) => {
      const room = await lockRoomFor(client, roomId, me);
      if (!room) return NOT_FOUND;
      if (room.owner_id === me) {
        const others = await client.query("SELECT 1 FROM rooms_users WHERE room = $1 AND user_id <> $2 LIMIT 1", [roomId, me]);
        if (others.rowCount > 0) {
          return { status: 409, body: { code: "OWNER_MUST_TRANSFER", message: "Transfira o cargo de dono antes de sair" } };
        }
      }
      return { ok: true, roomDeleted: await detach(client, roomId, me) };
    });
    if (!outcome.ok) return res.status(outcome.status).json(outcome.body);
    announce(req, roomId, me, outcome.roomDeleted);
    return res.status(200).json({ room: roomId, roomDeleted: outcome.roomDeleted });
  } catch (err) {
    return next(err);
  }
};

// Só o dono. Bane o removido e troca o convite (o novo é devolvido uma única
// vez, ao dono): quem saiu com o convite antigo não o repassa a ninguém.
const removeMember = async (req, res, next) => {
  const roomId = req.params.id;
  const target = req.params.userId;
  const me = req.session.userId;
  const invite = newInvite();
  try {
    const outcome = await withTransaction(async (client) => {
      const refused = await lockOwnedRoom(client, roomId, me);
      if (refused) return refused;
      if (target === me) return refuse(400, "Para sair da sala use POST /rooms/:id/leave");
      const isMember = await client.query("SELECT 1 FROM rooms_users WHERE room = $1 AND user_id = $2", [roomId, target]);
      if (isMember.rowCount === 0) return NOT_FOUND;
      await detach(client, roomId, target);
      await client.query("INSERT INTO room_bans (room, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", [roomId, target]);
      await setInvite(client, roomId, invite);
      return { ok: true };
    });
    if (!outcome.ok) return res.status(outcome.status).json(outcome.body);
    announce(req, roomId, target, false);
    return res.status(200).json({ room: roomId, userId: target, invite });
  } catch (err) {
    return next(err);
  }
};

// Só o dono, para um membro que tem a chave ATUAL (room_current_wraps): um
// dono sem a chave não conseguiria rotacioná-la nem entregá-la.
const transferOwner = async (req, res, next) => {
  const roomId = req.params.id;
  const target = req.body.userId;
  const me = req.session.userId;
  try {
    const outcome = await withTransaction(async (client) => {
      const refused = await lockOwnedRoom(client, roomId, me);
      if (refused) return refused;
      if (target === me) return refuse(400, "Você já é o dono");
      const { rows } = await client.query(
        `SELECT EXISTS (SELECT 1 FROM room_current_wraps w WHERE w.room = m.room AND w.recipient_id = m.user_id) AS has_key
         FROM rooms_users m WHERE m.room = $1 AND m.user_id = $2`,
        [roomId, target]
      );
      if (rows.length === 0) return NOT_FOUND;
      if (!rows[0].has_key) return refuse(409, "O novo dono precisa ter a chave atual da sala");
      await client.query("UPDATE rooms SET owner_id = $2 WHERE id = $1", [roomId, target]);
      return { ok: true };
    });
    if (!outcome.ok) return res.status(outcome.status).json(outcome.body);
    // Etapa 5: o novo dono re-assina o nome da sala (seq + 1); até lá os
    // clientes o mostram como "não verificado".
    req.app.locals.notify.ownerChanged(roomId, target);
    return res.status(200).json({ room: roomId, ownerId: target });
  } catch (err) {
    return next(err);
  }
};

// Só o dono: troca o convite (D5). O novo é devolvido uma única vez; o
// antigo deixa de valer para todos.
const rotateInvite = async (req, res, next) => {
  const roomId = req.params.id;
  const me = req.session.userId;
  const invite = newInvite();
  try {
    const outcome = await withTransaction(async (client) => {
      const refused = await lockOwnedRoom(client, roomId, me);
      if (refused) return refused;
      await setInvite(client, roomId, invite);
      return { ok: true };
    });
    if (!outcome.ok) return res.status(outcome.status).json(outcome.body);
    return res.status(200).json({ room: roomId, invite });
  } catch (err) {
    return next(err);
  }
};

module.exports = { SKIP_ROTATION_VALUE, NOT_FOUND, lockOwnedRoom, leaveRoom, removeMember, transferOwner, rotateInvite };
