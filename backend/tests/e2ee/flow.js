// Fluxo E2EE de um cliente honesto, para os testes: registrar chaves, criar
// sala com a chave versão 1, entregar a chave a quem entrou e recuperá-la.
// `user.call(method, path)` devolve uma requisição supertest já autenticada
// (agente do helpers.js ou cookie do tests/ws/helpers.js).
const e2ee = require("../../../shared/e2ee");

const asAgent = (user) => ({ ...user, call: (method, path) => user.agent[method](path) });
const asCookie = (srv, user) => ({ ...user, call: (method, path) => srv.http[method](path).set("Cookie", user.cookie) });

const registerKeys = async (user) => {
  user.identity = await e2ee.generateIdentity();
  user.pub = await e2ee.exportPublicKeys(user.identity);
  const res = await user.call("put", "/keys").send(user.pub);
  if (res.status !== 201) throw new Error(`PUT /keys: ${res.status}`);
  user.keyEpoch = res.body.keyEpoch;
  return user;
};

const wrapFor = (sender, { roomId, version = 1, roomKey, recipientId, recipientEcdhPub }) =>
  e2ee.wrapRoomKey({
    roomKey,
    roomId,
    version,
    senderId: sender.id,
    recipientId,
    recipientEcdhPub,
    senderEcdsaKey: sender.identity.ecdsa.privateKey,
  });

// Cria a sala, gera a chave da sala e publica a versão 1 com o próprio wrap.
const createKeyedRoom = async (owner, name = "Sala cifrada") => {
  const created = await owner.call("post", "/createRoom").send({ name });
  if (created.status !== 201) throw new Error(`createRoom: ${created.status}`);
  const roomId = created.body.id;
  const roomKey = await e2ee.generateRoomKey();
  const wrap = await wrapFor(owner, { roomId, roomKey, recipientId: owner.id, recipientEcdhPub: owner.pub.ecdhPub });
  const published = await owner.call("post", `/rooms/${roomId}/keys`).send({ version: 1, wrap });
  if (published.status !== 201) throw new Error(`POST /rooms/${roomId}/keys: ${published.status} ${JSON.stringify(published.body)}`);
  return { roomId, inviteKey: created.body.key, roomKey };
};

const join = async (user, room) => {
  const res = await user.call("post", "/joinRooms").send({ idRoom: room.roomId, key: room.inviteKey });
  if (res.status !== 200) throw new Error(`joinRooms: ${res.status}`);
};

// O remetente (que tem a chave) entrega um wrap ao destinatário.
const grant = async (sender, room, recipient) => {
  const wrap = await wrapFor(sender, {
    roomId: room.roomId,
    roomKey: room.roomKey,
    recipientId: recipient.id,
    recipientEcdhPub: recipient.pub.ecdhPub,
  });
  return sender
    .call("post", `/rooms/${room.roomId}/keys/wraps`)
    .send({ version: 1, recipientId: recipient.id, recipientKeyEpoch: recipient.keyEpoch, wrap });
};

// Busca os próprios wraps e abre o da versão atual, conferindo a assinatura
// com a chave pública ECDSA do remetente (obtida do diretório).
const fetchRoomKey = async (user, roomId) => {
  const res = await user.call("get", `/rooms/${roomId}/keys`);
  if (res.status !== 200) throw new Error(`GET /rooms/${roomId}/keys: ${res.status}`);
  const wrap = res.body.wraps.find((w) => w.version === res.body.currentVersion);
  const sender = await user.call("get", `/keys/${wrap.senderId}`);
  return e2ee.unwrapRoomKey({
    wrap,
    roomId,
    version: wrap.version,
    senderId: wrap.senderId,
    recipientId: user.id,
    recipientEcdhKey: user.identity.ecdh.privateKey,
    senderEcdsaPub: sender.body.ecdsaPub,
  });
};

module.exports = { asAgent, asCookie, registerKeys, wrapFor, createKeyedRoom, join, grant, fetchRoomKey };
