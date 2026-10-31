// Cliente E2EE do navegador: o equivalente do backend/tools/e2ee-session.js
// (que é Node e grava arquivos), com o cofre do IndexedDB (crypto/vault.js).
// Toda a criptografia e as verificações vêm de shared/e2ee; aqui ficam só as
// REGRAS do cliente, as mesmas do ws-client (docs/05 §5, §11 e §12):
//   - TOFU: a primeira chave pública vista de cada usuário é fixada; mudou →
//     "changed" e nada dele é aceito até conferir o número de segurança;
//   - chave da sala: wrap conferido com a chave FIXADA do remetente e o
//     compromisso do autor da versão; criador da v1 e maior versão fixados
//     por sala; a partir da v2, o autor tem de ser eu ou alguém VERIFICADO;
//     uma chave nova que repete outra versão é recusada;
//   - nome da sala: só o assinado pelo dono atual (openRoomName), com o
//     maior seq guardado no cofre;
//   - mensagens: createReceiver (deduplicação, assinatura, exp).
// `api(method, path, body)` → { status, body }. Nada aqui guarda texto
// decifrado: quem exibe é a interface, só em memória.
import e2ee from "../crypto/e2ee.js";
import { exportRoomKey, importRoomKey } from "../crypto/browser.js";

const TRUSTED = new Set(["verified", "unverified"]);

export class ClientError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "ClientError";
    this.code = code;
  }
}

const expect = (res, ...statuses) => {
  if (!statuses.includes(res.status)) throw new ClientError(`HTTP_${res.status}`, `resposta inesperada do servidor (${res.status})`);
  return res.body;
};

export const createClient = ({ api, me, vault, onNotice = () => {} }) => {
  const currentVersion = new Map(); // sala → versão atual informada pelo servidor
  const rotationRequired = new Map();
  const imported = new Map(); // `${sala}:${versão}` → CryptoKey
  let keyEpoch = null;

  const state = () => vault.state;

  // --- chaves públicas e trust store --------------------------------------

  const registerKeys = async () => {
    const mine = await api("get", `/keys/${me.id}`);
    if (mine.status === 404) {
      keyEpoch = expect(await api("put", "/keys", vault.pub), 201).keyEpoch;
      return;
    }
    const current = expect(mine, 200);
    if (current.ecdhPub !== vault.pub.ecdhPub || current.ecdsaPub !== vault.pub.ecdsaPub) {
      // Outro dispositivo ou cofre perdido: trocar as chaves no servidor é
      // decisão explícita do usuário (Parte C), nunca automática.
      throw new ClientError("KEYS_MISMATCH", "as chaves públicas no servidor não são as deste cofre (outro navegador ou cofre perdido)");
    }
    keyEpoch = current.keyEpoch;
  };

  // Busca a chave do usuário no diretório e passa pelo TOFU; null = sem chave.
  const observe = async (userId, keys) => {
    let pub = keys;
    if (!pub) {
      const res = await api("get", `/keys/${userId}`);
      if (res.status === 404) return null;
      pub = expect(res, 200);
    }
    const r = await e2ee.observeKeys(vault.trust, userId, pub);
    if (r.status !== "MATCH") await vault.saveTrust(r.store);
    if (r.status === "CHANGED") onNotice({ kind: "KEY_CHANGED", userId });
    return r.status;
  };

  const senderKeyFor = async (userId) => {
    if (userId === me.id) return { ecdsaPub: vault.pub.ecdsaPub, trust: "verified" };
    if (!vault.trust.peers[userId] && (await observe(userId)) === null) return { trust: "unknown" };
    const peer = vault.trust.peers[userId];
    if (peer.changed) return { trust: "changed" };
    return { ecdsaPub: peer.ecdsaPub, trust: peer.verified ? "verified" : "unverified" };
  };

  const trustOf = (userId) => {
    if (userId === me.id) return "verified";
    const peer = vault.trust.peers[userId];
    if (!peer) return "unknown";
    if (peer.changed) return "changed";
    return peer.verified ? "verified" : "unverified";
  };

  // --- chave da sala --------------------------------------------------------

  const roomKeysFor = async (room) => {
    const keys = {};
    for (const [version, raw] of Object.entries(state().roomKeys[room] ?? {})) {
      const id = `${room}:${version}`;
      if (!imported.has(id)) imported.set(id, await importRoomKey(raw));
      keys[version] = imported.get(id);
    }
    return keys;
  };

  const hasCurrentKey = (room) => {
    const version = currentVersion.get(room);
    return Boolean(version && state().roomKeys[room]?.[version]);
  };

  const storeRoomKey = async (room, version, roomKey, pin) => {
    const raw = await exportRoomKey(roomKey);
    const s = state();
    await vault.saveState({
      ...s,
      roomKeys: { ...s.roomKeys, [room]: { ...s.roomKeys[room], [version]: raw } },
      rooms: { ...s.rooms, [room]: pin },
    });
  };

  // Abre e guarda UM wrap. false se não conferir; um wrap da versão atual
  // que não confere é descartado no servidor (outro membro pode entregar um bom).
  const openWrap = async (room, keysState, wrap) => {
    const info = keysState.versions.find((v) => v.version === wrap.version);
    if (!info) return false;
    const pinned = state().rooms[room];
    if (wrap.version === 1 && pinned?.creator !== undefined && pinned.creator !== info.createdBy) {
      onNotice({ kind: "CREATOR_CHANGED", room });
      return false;
    }
    const sender = await senderKeyFor(wrap.senderId);
    const author = await senderKeyFor(info.createdBy);
    if (!TRUSTED.has(sender.trust) || !TRUSTED.has(author.trust)) return false;
    // A partir da v2, quem escolheu a chave é quem rotacionou: só eu ou
    // alguém VERIFICADO (achado da revisão da 4b-2).
    if (wrap.version > 1 && info.createdBy !== me.id && author.trust !== "verified") {
      onNotice({ kind: "ROTATED_BY_UNVERIFIED", room, userId: info.createdBy });
      return false;
    }
    let roomKey;
    try {
      roomKey = await e2ee.unwrapRoomKey({ wrap, roomId: room, version: wrap.version, senderId: wrap.senderId, recipientId: me.id, recipientEcdhKey: vault.identity.ecdh.privateKey, senderEcdsaPub: sender.ecdsaPub });
      await e2ee.verifyRoomKeyCommitment({ roomKey, roomId: room, version: wrap.version, commitment: info.commitment, commitmentSig: info.commitmentSig, creatorEcdsaPub: author.ecdsaPub });
      const raw = await exportRoomKey(roomKey);
      if (Object.values(state().roomKeys[room] ?? {}).includes(raw)) throw new e2ee.E2eeError("KEY_REUSED");
    } catch (err) {
      if (!(err instanceof e2ee.E2eeError)) throw err;
      if (wrap.version === keysState.currentVersion) {
        await api("delete", `/rooms/${room}/keys/wraps/mine`);
        onNotice({ kind: "BAD_WRAP", room });
      }
      return false;
    }
    const creator = pinned?.creator ?? (wrap.version === 1 ? info.createdBy : undefined);
    await storeRoomKey(room, wrap.version, roomKey, { creator, version: Math.max(wrap.version, pinned?.version ?? 0) });
    return true;
  };

  // Garante a chave atual da sala e abre as versões que faltam (o histórico
  // de antes de uma rotação continua legível). { ok, sender?, reason? }
  const ensureRoomKey = async (room) => {
    const keysState = expect(await api("get", `/rooms/${room}/keys`), 200);
    const pinned = state().rooms[room];
    if (pinned && keysState.currentVersion < pinned.version) {
      onNotice({ kind: "VERSION_ROLLBACK", room });
      return { ok: false, reason: "VERSION_ROLLBACK" };
    }
    currentVersion.set(room, keysState.currentVersion);
    rotationRequired.set(room, keysState.rotationRequired === true);
    if (hasCurrentKey(room)) return { ok: true };
    const missing = keysState.wraps
      .filter((w) => w.version <= keysState.currentVersion && !state().roomKeys[room]?.[w.version])
      .sort((a, b) => a.version - b.version);
    let sender;
    for (const wrap of missing) {
      if ((await openWrap(room, keysState, wrap)) && wrap.version === keysState.currentVersion) sender = wrap.senderId;
    }
    return hasCurrentKey(room) ? { ok: true, sender } : { ok: false, reason: "NO_KEY" };
  };

  // --- salas ----------------------------------------------------------------

  // Cria a sala: chave nova, o próprio wrap, o compromisso e o nome assinado
  // por mim (seq 1), tudo antes de qualquer outro membro existir. O nome é
  // conferido (tamanho) ANTES da primeira requisição.
  const createRoom = async (name) => {
    const probe = await e2ee.signRoomName({ roomId: 1, seq: 1, ownerId: me.id, name, ownerEcdsaKey: vault.identity.ecdsa.privateKey });
    if (!probe) throw new ClientError("INVALID_NAME");
    const created = expect(await api("post", "/createRoom", {}), 201);
    const roomId = created.id;
    const roomKey = await e2ee.generateRoomKey();
    const ctx = { roomId, version: 1 };
    const wrap = await e2ee.wrapRoomKey({ ...ctx, roomKey, senderId: me.id, recipientId: me.id, recipientEcdhPub: vault.pub.ecdhPub, senderEcdsaKey: vault.identity.ecdsa.privateKey });
    const commitment = await e2ee.commitRoomKey({ ...ctx, roomKey, creatorEcdsaKey: vault.identity.ecdsa.privateKey });
    const payload = await e2ee.signRoomName({ roomId, seq: 1, ownerId: me.id, name, ownerEcdsaKey: vault.identity.ecdsa.privateKey });
    const nameEnv = await e2ee.encryptRoomName({ roomKey, roomId, kv: 1, payload });
    expect(await api("post", `/rooms/${roomId}/keys`, { version: 1, wrap, ...commitment, nameEnv }), 201);
    await storeRoomKey(roomId, 1, roomKey, { creator: me.id, version: 1 });
    await vault.saveState({ ...state(), roomNames: { ...state().roomNames, [roomId]: payload } });
    currentVersion.set(roomId, 1);
    // O convite só aparece aqui, uma vez: quem chama mostra e não guarda.
    return { id: roomId, invite: created.key };
  };

  const joinRoom = async (roomId, invite) => {
    const res = await api("post", "/joinRooms", { idRoom: roomId, key: invite });
    if (res.status === 403) throw new ClientError("BAD_INVITE", "convite inválido");
    expect(res, 200);
  };

  const ownerKeyFor = async (ownerId) => {
    if (ownerId === me.id) return vault.pub.ecdsaPub;
    const owner = await senderKeyFor(ownerId);
    return TRUSTED.has(owner.trust) ? owner.ecdsaPub : null;
  };

  // Nome a exibir de uma entrada do GET /rooms (null → "Sala #id (nome não
  // verificado)"); o maior seq verificado vai para o cofre.
  const describeRoom = async (entry) => {
    const opened = await e2ee.openRoomName({
      nameEnv: entry.nameEnv,
      roomKeys: await roomKeysFor(entry.id),
      roomId: entry.id,
      ownerId: entry.ownerId,
      ownerEcdsaPub: await ownerKeyFor(entry.ownerId),
      last: state().roomNames[entry.id] ?? null,
    });
    if (opened.remember) await vault.saveState({ ...state(), roomNames: { ...state().roomNames, [entry.id]: opened.remember } });
    return {
      id: entry.id,
      name: opened.name,
      nameVerified: opened.verified,
      nameTampered: opened.tampered,
      ownerId: entry.ownerId,
      retentionSeconds: entry.retentionSeconds ?? null,
      unread: Number(entry.nummessages ?? 0),
    };
  };

  const listRooms = async () => {
    const rooms = expect(await api("get", "/rooms"), 200);
    const out = [];
    for (const entry of rooms) out.push(await describeRoom(entry));
    return out;
  };

  // --- mensagens ------------------------------------------------------------

  const receiver = e2ee.createReceiver({ roomKeysFor, senderKeyFor });

  const encrypt = async (room, cid, text, exp = null) => {
    const version = currentVersion.get(room);
    const keys = await roomKeysFor(room);
    if (!keys[version]) throw new ClientError("NO_KEY", "sem a chave atual da sala");
    return e2ee.encryptMessage({ roomKey: keys[version], kv: version, roomId: room, senderId: me.id, cid, text, senderEcdsaKey: vault.identity.ecdsa.privateKey, exp });
  };

  // Mensagem que não verifica pode ser de quem trocou de chave: confere o
  // diretório (CHAVE ALTERADA). kv maior que o conhecido: busca a chave nova.
  const accept = async (packet) => {
    let result = await receiver.accept(packet);
    if (result.status === "missing_key" && result.kv > (currentVersion.get(packet.room) ?? 0)) {
      await ensureRoomKey(packet.room);
      result = await receiver.accept(packet);
    }
    if (result.status === "invalid" && packet.from !== me.id && (await observe(packet.from)) === "CHANGED") {
      return { status: "untrusted", trust: "changed" };
    }
    return result;
  };

  // Histórico paginado (as `limit` mais recentes antes de `before`), já
  // decifrado e verificado, em ordem crescente de id.
  const history = async (room, { before, limit = 50 } = {}) => {
    const query = new URLSearchParams({ limit: String(limit), ...(before ? { before: String(before) } : {}) });
    const rows = expect(await api("get", `/messages/${room}?${query}`), 200);
    const out = [];
    for (const row of rows) {
      const packet = { room, id: row.idmessage, from: row.userid, cid: row.cid, ts: row.dtmessage, body: row.message };
      out.push({ packet, result: await accept(packet) });
    }
    return out;
  };

  return {
    registerKeys,
    observe,
    senderKeyFor,
    trustOf,
    ensureRoomKey,
    hasCurrentKey,
    currentVersion: (room) => currentVersion.get(room),
    rotationRequired: (room) => rotationRequired.get(room) === true,
    createRoom,
    joinRoom,
    listRooms,
    describeRoom,
    encrypt,
    accept,
    history,
    keyEpoch: () => keyEpoch,
  };
};
