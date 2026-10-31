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
  // Falhar FECHADO (revisão C7): quem não deu para conferir (diretório fora
  // do ar, cofre sem gravar) fica "unchecked"; uma CHAVE ALTERADA que o
  // cofre não gravou continua "changed" na memória desta aba.
  const unchecked = new Set();
  const memChanged = new Set();
  const memKicked = new Set(); // `${sala}:${userId}` removidos cujo registro no cofre falhou

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
    let status;
    try {
      let pub = keys;
      if (!pub) {
        const res = await api("get", `/keys/${userId}`);
        if (res.status === 404) {
          unchecked.delete(userId);
          return null;
        }
        pub = expect(res, 200);
      }
      await vault.updateTrust(async (trust) => {
        const r = await e2ee.observeKeys(trust, userId, pub);
        status = r.status;
        return r.status === "MATCH" ? trust : r.store;
      });
    } catch (err) {
      if (status === "CHANGED") {
        memChanged.add(userId);
        onNotice({ kind: "KEY_CHANGED", userId });
        onNotice({ kind: "VAULT_WRITE_FAILED" });
      } else {
        unchecked.add(userId);
      }
      throw err;
    }
    unchecked.delete(userId);
    if (status === "CHANGED") onNotice({ kind: "KEY_CHANGED", userId });
    return status;
  };

  const senderKeyFor = async (userId) => {
    if (userId === me.id) return { ecdsaPub: vault.pub.ecdsaPub, trust: "verified" };
    if (memChanged.has(userId)) return { trust: "changed" };
    if (!vault.trust.peers[userId] && (await observe(userId)) === null) return { trust: "unknown" };
    const peer = vault.trust.peers[userId];
    if (peer.changed) return { trust: "changed" };
    return { ecdsaPub: peer.ecdsaPub, trust: peer.verified ? "verified" : "unverified" };
  };

  const trustOf = (userId) => {
    if (userId === me.id) return "verified";
    if (memChanged.has(userId)) return "changed";
    if (unchecked.has(userId)) return "unchecked";
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

  // pin(atual) → o que fica fixado da sala, calculado sobre o estado MAIS
  // RECENTE (nunca sobre uma cópia antiga: vault.updateState é serial).
  const storeRoomKey = async (room, version, roomKey, pin) => {
    const raw = await exportRoomKey(roomKey);
    await vault.updateState((s) => ({
      ...s,
      roomKeys: { ...s.roomKeys, [room]: { ...s.roomKeys[room], [version]: raw } },
      rooms: { ...s.rooms, [room]: pin(s.rooms[room]) },
    }));
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
    await storeRoomKey(room, wrap.version, roomKey, (current) => ({
      creator: current?.creator ?? (wrap.version === 1 ? info.createdBy : undefined),
      version: Math.max(wrap.version, current?.version ?? 0),
    }));
    return true;
  };

  // Garante a chave atual da sala e abre as versões que faltam (o histórico
  // de antes de uma rotação continua legível). { ok, sender?, reason? }
  // Chamadas simultâneas para a mesma sala compartilham UMA execução.
  const inflight = new Map();
  const ensureRoomKey = (room) => {
    if (!inflight.has(room)) inflight.set(room, ensureRoomKeyOnce(room).finally(() => inflight.delete(room)));
    return inflight.get(room);
  };
  const ensureRoomKeyOnce = async (room) => {
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
    await storeRoomKey(roomId, 1, roomKey, () => ({ creator: me.id, version: 1 }));
    await vault.updateState((s) => ({ ...s, roomNames: { ...s.roomNames, [roomId]: payload } }));
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
    if (opened.remember) {
      // Só sobe o seq: outra operação simultânea pode já ter guardado um maior.
      await vault.updateState((s) =>
        (s.roomNames[entry.id]?.seq ?? 0) >= opened.remember.seq ? s : { ...s, roomNames: { ...s.roomNames, [entry.id]: opened.remember } }
      );
    }
    return {
      id: entry.id,
      name: opened.name,
      nameVerified: opened.verified,
      nameTampered: opened.tampered,
      namePayload: opened.payload,
      seenSeq: opened.seenSeq,
      ownerId: entry.ownerId,
      retentionSeconds: entry.retentionSeconds ?? null,
      unread: Number(entry.nummessages ?? 0),
    };
  };

  const listRooms = async () => {
    const rooms = expect(await api("get", "/rooms"), 200);
    const out = [];
    for (const entry of rooms) {
      // Uma sala que não deu para conferir não derruba a lista: aparece como
      // "nome não verificado" (nameError), sem nome.
      try {
        out.push(await describeRoom(entry));
      } catch {
        out.push({ id: entry.id, name: null, nameVerified: false, nameTampered: false, nameError: true, namePayload: null, seenSeq: null, ownerId: entry.ownerId, retentionSeconds: entry.retentionSeconds ?? null, unread: Number(entry.nummessages ?? 0) });
      }
    }
    return out;
  };

  // Membros da sala (id e nome de exibição): o nome é dado do servidor, só
  // exibido como TEXTO.
  const members = async (room) => expect(await api("get", `/roomUsers/${room}`), 200);

  const roomEntry = async (room) => {
    const entry = expect(await api("get", "/rooms"), 200).find((r) => r.id === room);
    if (!entry) throw new ClientError("NOT_MEMBER", "você não está nesta sala");
    return describeRoom(entry);
  };

  // --- verificação (C1) -----------------------------------------------------

  // Número de segurança com a chave CANDIDATA (a pendente, se mudou); a
  // fingerprint devolvida é a que a confirmação tem de citar.
  const safety = async (userId) => {
    if (!vault.trust.peers[userId] && (await observe(userId)) === null) throw new ClientError("NO_KEYS", "usuário sem chave pública");
    const peer = vault.trust.peers[userId];
    const candidate = peer.changed ?? peer;
    const number = await e2ee.safetyNumber({ userId: me.id, ...vault.pub }, { userId, ecdhPub: candidate.ecdhPub, ecdsaPub: candidate.ecdsaPub });
    return { number, fingerprint: candidate.fingerprint, changed: Boolean(peer.changed) };
  };

  // Só confirma a chave cuja fingerprint FOI EXIBIDA (confirmTrust recusa se
  // a chave pendente mudou entre a exibição e a confirmação).
  const confirm = (userId, shownFingerprint) => vault.updateTrust((trust) => e2ee.confirmTrust(trust, userId, shownFingerprint));

  // --- entrega da chave e rotação (C1) ---------------------------------------

  // Aprovações explícitas (/approve), só nesta aba: valem para a entrega e
  // para a próxima rotação, e caem quando a pessoa deixa de ser membro.
  const approved = new Set();
  const isKicked = (room, userId) => memKicked.has(`${room}:${userId}`) || (state().kicked[room] ?? []).includes(userId);

  const pendingOf = async (room) => {
    const res = await api("get", `/rooms/${room}/keys/pending`);
    if (res.status === 403) return null; // não tenho a chave atual
    return expect(res, 200);
  };

  const deliverTo = async (room, version, roomKey, pending) => {
    const wrap = await e2ee.wrapRoomKey({ roomKey, roomId: room, version, senderId: me.id, recipientId: pending.userId, recipientEcdhPub: pending.keys.ecdhPub, senderEcdsaKey: vault.identity.ecdsa.privateKey });
    expect(await api("post", `/rooms/${room}/keys/wraps`, { version, recipientId: pending.userId, recipientKeyEpoch: pending.keys.keyEpoch, wrap }), 201);
  };

  // Pendentes: chave conferida no trust store (CHAVE ALTERADA → nunca);
  // entrega automática só a VERIFICADOS ou aprovados; os demais voltam em
  // awaitingApproval para a interface pedir a decisão.
  const distribute = async (room) => {
    const out = { delivered: [], awaitingApproval: [] };
    if (!hasCurrentKey(room)) return out;
    const res = await pendingOf(room);
    if (!res) return out;
    const roomKey = (await roomKeysFor(room))[res.version];
    if (!roomKey) return out;
    for (const pending of res.pending) {
      if (!pending.keys || isKicked(room, pending.userId)) continue;
      await observe(pending.userId, pending.keys);
      const trust = e2ee.trustState(vault.trust, pending.userId, pending.keys);
      if (trust === "changed") continue;
      if (trust === "verified" || approved.has(`${room}:${pending.userId}`)) {
        await deliverTo(room, res.version, roomKey, pending);
        out.delivered.push(pending.userId);
      } else {
        out.awaitingApproval.push({ userId: pending.userId, name: pending.name, fingerprint: vault.trust.peers[pending.userId].fingerprint, trust });
      }
    }
    return out;
  };

  const approve = async (room, userId) => {
    if (!hasCurrentKey(room)) throw new ClientError("NO_KEY", "você não tem a chave atual desta sala");
    const res = await pendingOf(room);
    const pending = res?.pending.find((p) => p.userId === userId);
    if (!pending?.keys) throw new ClientError("NOT_PENDING", "este usuário não está aguardando a chave");
    if (isKicked(room, userId)) throw new ClientError("KICKED", "você removeu este usuário desta sala");
    await observe(userId, pending.keys);
    if (e2ee.trustState(vault.trust, userId, pending.keys) === "changed") throw new ClientError("KEY_CHANGED", "CHAVE ALTERADA: confira o número de segurança antes");
    approved.add(`${room}:${userId}`);
    await deliverTo(room, res.version, (await roomKeysFor(room))[res.version], pending);
  };

  // Quem entra numa rotação: eu e quem está VERIFICADO, ou NÃO VERIFICADO e
  // aprovado nesta sala. Os demais ficam de fora e voltam a ser pendentes.
  const rotationRecipients = async (room) => {
    const list = await members(room);
    const ids = new Set(list.map((m) => m.id));
    for (const key of [...approved]) {
      const [r, u] = key.split(":").map(Number);
      if (r === room && !ids.has(u)) approved.delete(key);
    }
    const recipients = [{ userId: me.id, keyEpoch, ecdhPub: vault.pub.ecdhPub }];
    const left = [];
    for (const m of list) {
      if (m.id === me.id) continue;
      const res = isKicked(room, m.id) ? null : await api("get", `/keys/${m.id}`);
      if (!res || res.status !== 200) {
        left.push(m.id);
        continue;
      }
      await observe(m.id, res.body);
      const trust = e2ee.trustState(vault.trust, m.id, res.body);
      if (trust === "verified" || (trust === "unverified" && approved.has(`${room}:${m.id}`))) {
        recipients.push({ userId: m.id, keyEpoch: res.body.keyEpoch, ecdhPub: res.body.ecdhPub });
      } else left.push(m.id);
    }
    return { recipients, left };
  };

  // Chave NOVA de getRandomValues (nunca derivada da anterior), compromisso
  // e wraps assinados por mim, e o MESMO nome assinado pelo dono recifrado
  // com a chave nova (null se não há um válido). 409 STALE_MEMBERSHIP →
  // monta de novo; outro 409 = outro membro rotacionou antes.
  const rotate = async (room, { attempts = 3, expectVersion } = {}) => {
    const got = await ensureRoomKey(room);
    if (expectVersion !== undefined && currentVersion.get(room) !== expectVersion) return { rotated: false, reason: "concurrent" };
    if (!got.ok) throw new ClientError("NO_KEY", "você não tem a chave atual desta sala");
    const { namePayload } = await roomEntry(room);
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const version = currentVersion.get(room) + 1;
      const { recipients, left } = await rotationRecipients(room);
      const roomKey = await e2ee.generateRoomKey();
      const ctx = { roomId: room, version };
      const commitment = await e2ee.commitRoomKey({ ...ctx, roomKey, creatorEcdsaKey: vault.identity.ecdsa.privateKey });
      const wraps = [];
      for (const r of recipients) {
        const wrap = await e2ee.wrapRoomKey({ ...ctx, roomKey, senderId: me.id, recipientId: r.userId, recipientEcdhPub: r.ecdhPub, senderEcdsaKey: vault.identity.ecdsa.privateKey });
        wraps.push({ recipientId: r.userId, recipientKeyEpoch: r.keyEpoch, wrap });
      }
      const nameEnv = namePayload ? await e2ee.encryptRoomName({ roomKey, roomId: room, kv: version, payload: namePayload }) : null;
      const res = await api("post", `/rooms/${room}/keys/rotate`, { version, ...commitment, wraps, nameEnv });
      if (res.status === 201) {
        await storeRoomKey(room, version, roomKey, (current) => ({ creator: current?.creator, version }));
        currentVersion.set(room, version);
        rotationRequired.set(room, false);
        return { rotated: true, version, left };
      }
      if (res.status === 409 && res.body?.code === "STALE_MEMBERSHIP") continue;
      if (res.status === 409) {
        await ensureRoomKey(room);
        return { rotated: false, reason: "concurrent" };
      }
      throw new ClientError(`HTTP_${res.status}`, "o servidor recusou a troca da chave");
    }
    return { rotated: false, reason: "stale" };
  };

  // ROTATION_PENDING: quem tem a chave tenta depois de 0 a 2 s aleatórios
  // (menos colisão entre membros); se a versão subiu nesse tempo, outro fez.
  const autoRotate = async (room, { maxDelayMs = 2000 } = {}) => {
    const seen = currentVersion.get(room);
    if (!hasCurrentKey(room)) return { rotated: false, reason: "no-key" };
    const [x] = globalThis.crypto.getRandomValues(new Uint16Array(1));
    await new Promise((resolve) => setTimeout(resolve, Math.floor((x / 65536) * maxDelayMs)));
    return rotate(room, { expectVersion: seen });
  };

  // --- composição da sala e ajustes do dono (C1, C2) --------------------------

  // Remover: o servidor bane e troca o convite (devolvido uma vez); o
  // removido fica no cofre e nunca volta a receber a chave deste cliente.
  // Quem chama rotaciona em seguida (ou o ROTATION_PENDING o faz).
  const kick = async (room, userId) => {
    const removed = expect(await api("delete", `/rooms/${room}/members/${userId}`), 200);
    approved.delete(`${room}:${userId}`);
    // O servidor JÁ removeu: daqui para baixo nada pode esconder o convite
    // novo. Se o cofre não gravar, o bloqueio vale na memória desta aba.
    memKicked.add(`${room}:${userId}`);
    try {
      await vault.updateState((s) => ({ ...s, kicked: { ...s.kicked, [room]: [...new Set([...(s.kicked[room] ?? []), userId])] } }));
      return { invite: removed.invite, saved: true };
    } catch {
      onNotice({ kind: "VAULT_WRITE_FAILED" });
      return { invite: removed.invite, saved: false };
    }
  };

  const leave = async (room) => {
    const res = await api("post", `/rooms/${room}/leave`);
    if (res.status === 409 && res.body?.code === "OWNER_MUST_TRANSFER") throw new ClientError("OWNER_MUST_TRANSFER", "transfira o cargo de dono antes de sair");
    return expect(res, 200);
  };

  const transferOwner = async (room, userId) => {
    const res = await api("post", `/rooms/${room}/owner`, { userId });
    if (res.status === 409) throw new ClientError("TARGET_NO_KEY", "o novo dono precisa ter a chave atual da sala");
    return expect(res, 200);
  };

  const rotateInvite = async (room) => expect(await api("post", `/rooms/${room}/invite/rotate`), 200).invite;
  const bans = async (room) => expect(await api("get", `/rooms/${room}/bans`), 200).bans;
  const unban = async (room, userId) => expect(await api("delete", `/rooms/${room}/bans/${userId}`), 204);

  const setRetention = async (room, retentionSeconds) => {
    const res = await api("put", `/rooms/${room}/retention`, { retentionSeconds });
    if (res.status === 400) throw new ClientError("BAD_RETENTION", "retenção inválida");
    return expect(res, 200).retentionSeconds;
  };

  // Só o dono: seq acima do maior visto (nextRoomNameSeq limita o que um
  // seq não verificado pode adiantar), assinado e cifrado com a chave atual.
  const signAndPublishName = async (room, name, info) => {
    await ensureRoomKey(room);
    const version = currentVersion.get(room);
    const roomKey = (await roomKeysFor(room))[version];
    if (!roomKey) throw new ClientError("NO_KEY", "você não tem a chave atual desta sala");
    const seq = e2ee.nextRoomNameSeq(state().roomNames[room]?.seq, info.seenSeq);
    const payload = await e2ee.signRoomName({ roomId: room, seq, ownerId: me.id, name, ownerEcdsaKey: vault.identity.ecdsa.privateKey });
    const res = await api("put", `/rooms/${room}/name`, { nameEnv: await e2ee.encryptRoomName({ roomKey, roomId: room, kv: version, payload }) });
    if (res.status === 409 && res.body?.code === "ROTATION_PENDING") throw new ClientError("ROTATION_PENDING", "a chave precisa ser trocada antes");
    expect(res, 200);
    await vault.updateState((s) => ({ ...s, roomNames: { ...s.roomNames, [room]: payload } }));
  };

  const rename = async (room, name) => signAndPublishName(room, name, await roomEntry(room));

  // Quem virou dono re-assina o último nome verificado com seq + 1 (o do dono
  // anterior deixa de valer para os outros). true se re-assinou.
  const ensureOwnerSignature = async (room) => {
    const info = await roomEntry(room);
    if (info.ownerId !== me.id || info.namePayload?.ownerId === me.id) return false;
    const last = state().roomNames[room];
    if (!last) return false;
    await signAndPublishName(room, last.name, info);
    return true;
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
    if (result.status === "invalid" && packet.from !== me.id) {
      // Conferir de novo o diretório é só para explicar MELHOR a recusa:
      // se falhar, a mensagem continua "inválida" (nunca some).
      const status = await observe(packet.from).catch(() => null);
      if (status === "CHANGED") return { status: "untrusted", trust: "changed" };
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
    // ROTATION_PENDING recebido: bloqueia o envio já, antes de reler o servidor.
    markRotationRequired: (room) => rotationRequired.set(room, true),
    createRoom,
    joinRoom,
    listRooms,
    describeRoom,
    members,
    safety,
    confirm,
    distribute,
    approve,
    rotate,
    autoRotate,
    kick,
    leave,
    transferOwner,
    rotateInvite,
    bans,
    unban,
    setRetention,
    rename,
    ensureOwnerSignature,
    isKicked,
    encrypt,
    accept,
    history,
    keyEpoch: () => keyEpoch,
  };
};
