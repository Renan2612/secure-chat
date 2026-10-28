// Estado E2EE do cliente de referência (docs/05-e2ee.md): keystore cifrado
// (identidade + chaves de sala recebidas), trust store (TOFU), registro das
// chaves no diretório, chave da sala (criar, receber, entregar) e mensagens.
//
// `api(method, path, body)` faz a requisição autenticada e devolve
// { status, body }. Nada aqui imprime segredos: só ids, fingerprints e
// estados.
const e2ee = require("../../shared/e2ee");
const files = require("../../shared/e2ee/node");

// Texto vindo de outros usuários ou do servidor (mensagens, nomes, códigos)
// é impresso com os caracteres de controle VISÍVEIS (\u001b...): sem isso,
// uma mensagem com sequências de escape ANSI poderia apagar a tela, mudar o
// título do terminal ou forjar linhas como "[verificado]".
const clean = (value) =>
  String(value).replace(/[\u0000-\u001f\u007f-\u009f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);

const ok = (res, ...statuses) => {
  if (!statuses.includes(res.status)) throw new Error(`resposta inesperada do servidor (${res.status})`);
  return res.body;
};

class E2eeSession {
  constructor({ api, me, email, keystorePath, passphrase, print }) {
    Object.assign(this, { api, me, email, keystorePath, passphrase, print });
    this.trustPath = files.trustStorePath(keystorePath);
    this.currentVersion = new Map(); // sala → versão atual da chave
    this.importedKeys = new Map(); // `${sala}:${versão}` → CryptoKey
    this.shownFingerprint = new Map(); // userId → fingerprint exibida no /safety
    // Quem decide quem é membro é o SERVIDOR: a chave da sala só é entregue
    // automaticamente a quem o usuário VERIFICOU (/trust); os demais só com
    // aprovação explícita (/approve), senão um admin malicioso inseriria um
    // "membro fantasma" e receberia a chave dos clientes honestos.
    this.approved = new Set(); // `${sala}:${userId}`
    this.announced = new Set();
    this.receiver = e2ee.createReceiver({
      roomKeysFor: (room) => this.roomKeysFor(room),
      senderKeyFor: (userId) => this.senderKeyFor(userId),
    });
  }

  // Abre o keystore (ou cria um com identidade nova) e o trust store. Senha
  // errada ou arquivo adulterado: erro, e NADA é sobrescrito.
  async open() {
    const exists = require("node:fs").existsSync(this.keystorePath);
    if (exists) {
      this.data = await files.readSealedFile(this.keystorePath, this.passphrase);
      if (this.data.userId !== this.me.id) {
        throw new Error(`o keystore ${this.keystorePath} é de outro usuário (${this.data.userId}); use --keystore`);
      }
    } else {
      const identity = await e2ee.generateIdentity();
      this.data = { v: 1, userId: this.me.id, email: this.email, identity: await e2ee.exportIdentity(identity), roomKeys: {}, rooms: {} };
      await this.save();
      this.print(`keystore novo criado em ${this.keystorePath} (sem recuperação: guarde o arquivo e a senha de cifragem)`);
    }
    this.data.rooms = this.data.rooms ?? {}; // sala → { creator, version } fixados (TOFU por sala)
    this.identity = await e2ee.importIdentity(this.data.identity);
    this.pub = await e2ee.exportPublicKeys(this.identity);
    this.trust = require("node:fs").existsSync(this.trustPath)
      ? await files.readSealedFile(this.trustPath, this.passphrase)
      : e2ee.emptyTrustStore();
  }

  save() {
    return files.writeSealedFile(this.keystorePath, this.passphrase, this.data);
  }

  saveTrust() {
    return files.writeSealedFile(this.trustPath, this.passphrase, this.trust);
  }

  // Registra as chaves públicas no diretório, ou confere as que já estão lá.
  async registerKeys({ reset = false } = {}) {
    const mine = await this.api("get", `/keys/${this.me.id}`);
    if (mine.status === 404) {
      this.keyEpoch = ok(await this.api("put", "/keys", this.pub), 201).keyEpoch;
      return;
    }
    const current = ok(mine, 200);
    if (current.ecdhPub === this.pub.ecdhPub && current.ecdsaPub === this.pub.ecdsaPub) {
      this.keyEpoch = current.keyEpoch;
      return;
    }
    if (!reset) {
      throw new Error(
        "as chaves públicas no servidor não são as deste keystore (outro dispositivo ou keystore perdido). " +
          "Use --reset-keys para substituí-las: os outros verão CHAVE ALTERADA e você só volta às salas quando alguém lhe entregar a chave de novo"
      );
    }
    this.keyEpoch = ok(await this.api("post", "/keys/reset", this.pub), 200).keyEpoch;
    this.data.roomKeys = {}; // os wraps antigos foram apagados no servidor
    await this.save();
    this.print(`chaves substituídas no servidor (key_epoch ${this.keyEpoch})`);
  }

  // --- trust store ---------------------------------------------------------

  // Busca a chave do usuário no diretório e passa pelo TOFU. Devolve o
  // status (PINNED, MATCH, CHANGED) ou null se ele não tem chave.
  async observe(userId, keys) {
    let pub = keys;
    if (!pub) {
      const res = await this.api("get", `/keys/${userId}`);
      if (res.status === 404) return null;
      pub = ok(res, 200);
    }
    const r = await e2ee.observeKeys(this.trust, userId, pub);
    if (r.status !== "MATCH") {
      this.trust = r.store;
      await this.saveTrust();
    }
    if (r.status === "CHANGED") {
      this.print(`! CHAVE ALTERADA de usuário ${clean(userId)}: nada dele é aceito e a chave da sala não lhe é entregue até você conferir (/safety ${userId}) e confirmar (/trust ${userId})`);
    }
    return r.status;
  }

  // Chave ECDSA FIXADA do remetente (nunca a que o servidor manda na hora).
  async senderKeyFor(userId) {
    if (userId === this.me.id) return { ecdsaPub: this.pub.ecdsaPub, trust: "verified" };
    if (!this.trust.peers[userId] && (await this.observe(userId)) === null) return { trust: "unknown" };
    const peer = this.trust.peers[userId];
    if (peer.changed) return { trust: "changed" };
    return { ecdsaPub: peer.ecdsaPub, trust: peer.verified ? "verified" : "unverified" };
  }

  async safety(userId) {
    if (!this.trust.peers[userId] && (await this.observe(userId)) === null) throw new Error(`usuário ${userId} sem chave pública visível`);
    const peer = this.trust.peers[userId];
    const candidate = peer.changed ?? peer;
    const number = await e2ee.safetyNumber({ userId: this.me.id, ...this.pub }, { userId, ecdhPub: candidate.ecdhPub, ecdsaPub: candidate.ecdsaPub });
    this.shownFingerprint.set(userId, candidate.fingerprint);
    return { number, changed: Boolean(peer.changed) };
  }

  // Só confirma a chave cujo número de segurança FOI EXIBIDO (/safety).
  async confirm(userId) {
    const shown = this.shownFingerprint.get(userId);
    if (!shown) throw new Error(`use /safety ${userId} antes de /trust ${userId}`);
    this.trust = e2ee.confirmTrust(this.trust, userId, shown);
    this.shownFingerprint.delete(userId);
    await this.saveTrust();
  }

  trustLabel(userId) {
    const peer = this.trust.peers[userId];
    if (!peer) return "desconhecido";
    if (peer.changed) return "CHAVE ALTERADA";
    return peer.verified ? "verificado" : "não verificado";
  }

  // --- chave da sala --------------------------------------------------------

  async roomKeysFor(room) {
    const stored = this.data.roomKeys[room] ?? {};
    const keys = {};
    for (const [version, raw] of Object.entries(stored)) {
      const id = `${room}:${version}`;
      if (!this.importedKeys.has(id)) {
        this.importedKeys.set(id, await e2ee.primitives.importAesKey(e2ee.encoding.fromB64url(raw), ["encrypt", "decrypt"], true));
      }
      keys[version] = this.importedKeys.get(id);
    }
    return keys;
  }

  hasCurrentKey(room) {
    const version = this.currentVersion.get(room);
    return Boolean(version && this.data.roomKeys[room]?.[version]);
  }

  async storeRoomKey(room, version, roomKey) {
    this.data.roomKeys[room] = { ...this.data.roomKeys[room], [version]: e2ee.encoding.toB64url(await e2ee.primitives.exportRaw(roomKey)) };
    await this.save();
  }

  async createRoom(name) {
    const created = ok(await this.api("post", "/createRoom", { name }), 201);
    const roomKey = await e2ee.generateRoomKey();
    const ctx = { roomId: created.id, version: 1 };
    const wrap = await e2ee.wrapRoomKey({ ...ctx, roomKey, senderId: this.me.id, recipientId: this.me.id, recipientEcdhPub: this.pub.ecdhPub, senderEcdsaKey: this.identity.ecdsa.privateKey });
    const commitment = await e2ee.commitRoomKey({ ...ctx, roomKey, creatorEcdsaKey: this.identity.ecdsa.privateKey });
    ok(await this.api("post", `/rooms/${created.id}/keys`, { version: 1, wrap, ...commitment }), 201);
    this.data.rooms[created.id] = { creator: this.me.id, version: 1 };
    await this.storeRoomKey(created.id, 1, roomKey);
    this.currentVersion.set(created.id, 1);
    return created;
  }

  // Garante a chave atual da sala: já guardada, ou abre o próprio wrap
  // (assinatura do remetente e compromisso do criador conferidos com as
  // chaves FIXADAS). Wrap que não confere é descartado no servidor. O criador
  // e a maior versão vistos de cada sala ficam FIXADOS no keystore: o
  // servidor não pode, depois, apresentar outro "criador" nem voltar versão.
  // Devolve { ok, sender } (sender = quem entregou, para mostrar a confiança).
  async ensureRoomKey(room) {
    const state = ok(await this.api("get", `/rooms/${room}/keys`), 200);
    const pinned = this.data.rooms[room];
    if (pinned && state.currentVersion < pinned.version) {
      this.print(`! o servidor informa a versão ${state.currentVersion} da chave da sala ${room}, menor que a já vista (${pinned.version}): recusada`);
      return { ok: false };
    }
    this.currentVersion.set(room, state.currentVersion);
    if (this.hasCurrentKey(room)) return { ok: true };
    const wrap = state.wraps.find((w) => w.version === state.currentVersion);
    const info = state.versions.find((v) => v.version === state.currentVersion);
    if (!wrap || !info) return { ok: false };
    if (pinned && pinned.creator !== info.createdBy) {
      this.print(`! o criador da sala ${room} informado pelo servidor mudou (era usuário ${pinned.creator}, agora ${clean(info.createdBy)}): chave recusada`);
      return { ok: false };
    }
    const sender = await this.senderKeyFor(wrap.senderId);
    const creator = await this.senderKeyFor(info.createdBy);
    if (!["verified", "unverified"].includes(sender.trust) || !["verified", "unverified"].includes(creator.trust)) {
      this.print(`! a chave da sala ${room} veio de quem tem chave não confiável (usuário ${wrap.senderId}); não aceita`);
      return { ok: false };
    }
    try {
      const roomKey = await e2ee.unwrapRoomKey({ wrap, roomId: room, version: wrap.version, senderId: wrap.senderId, recipientId: this.me.id, recipientEcdhKey: this.identity.ecdh.privateKey, senderEcdsaPub: sender.ecdsaPub });
      await e2ee.verifyRoomKeyCommitment({ roomKey, roomId: room, version: wrap.version, commitment: info.commitment, commitmentSig: info.commitmentSig, creatorEcdsaPub: creator.ecdsaPub });
      this.data.rooms[room] = { creator: info.createdBy, version: Math.max(wrap.version, pinned?.version ?? 0) };
      await this.storeRoomKey(room, wrap.version, roomKey);
      return { ok: true, sender: wrap.senderId };
    } catch (err) {
      this.print(`! a chave recebida para a sala ${room} não confere (${clean(err.code ?? err.message)}); descartando o wrap e aguardando outro`);
      await this.api("delete", `/rooms/${room}/keys/wraps/mine`);
      return { ok: false };
    }
  }

  async pendingOf(room) {
    const res = await this.api("get", `/rooms/${room}/keys/pending`);
    return res.status === 200 ? res.body : null;
  }

  async deliverTo(room, version, roomKey, pending) {
    const wrap = await e2ee.wrapRoomKey({ roomKey, roomId: room, version, senderId: this.me.id, recipientId: pending.userId, recipientEcdhPub: pending.keys.ecdhPub, senderEcdsaKey: this.identity.ecdsa.privateKey });
    const posted = await this.api("post", `/rooms/${room}/keys/wraps`, { version, recipientId: pending.userId, recipientKeyEpoch: pending.keys.keyEpoch, wrap });
    if (posted.status === 201) this.print(`chave da sala entregue a usuário ${pending.userId} (${clean(pending.name)})`);
  }

  // Pendentes: a chave pública de cada um é conferida no trust store (CHAVE
  // ALTERADA → nunca entrega). Entrega automática só a quem foi VERIFICADO
  // ou aprovado (/approve); os demais são anunciados uma vez, com a
  // fingerprint, para o usuário decidir.
  async distribute(room) {
    if (!this.hasCurrentKey(room)) return;
    const res = await this.pendingOf(room);
    if (!res) return;
    const roomKey = (await this.roomKeysFor(room))[res.version];
    if (!roomKey) return;
    for (const pending of res.pending) {
      if (!pending.keys) continue; // ainda não registrou chaves públicas
      await this.observe(pending.userId, pending.keys);
      const state = e2ee.trustState(this.trust, pending.userId, pending.keys);
      if (state === "changed") continue;
      if (state === "verified" || this.approved.has(`${room}:${pending.userId}`)) {
        await this.deliverTo(room, res.version, roomKey, pending);
      } else if (!this.announced.has(`${room}:${pending.userId}`)) {
        this.announced.add(`${room}:${pending.userId}`);
        this.print(
          `usuário ${pending.userId} (${clean(pending.name)}) entrou na sala ${room} e aguarda a chave; ` +
            `fingerprint ${pending.keys.fingerprint.slice(0, 16)} [${this.trustLabel(pending.userId)}]. ` +
            `Se você espera essa pessoa na sala: confira /safety ${pending.userId} e entregue com /approve ${pending.userId}`
        );
      }
    }
  }

  // O usuário aprova a entrega da chave da sala a um pendente específico.
  async approve(room, userId) {
    if (!this.hasCurrentKey(room)) throw new Error("você ainda não tem a chave desta sala");
    const res = await this.pendingOf(room);
    const pending = res?.pending.find((p) => p.userId === userId);
    if (!pending) throw new Error(`usuário ${userId} não está aguardando a chave da sala ${room}`);
    if (!pending.keys) throw new Error(`usuário ${userId} ainda não registrou chaves públicas`);
    await this.observe(userId, pending.keys);
    if (e2ee.trustState(this.trust, userId, pending.keys) === "changed") {
      throw new Error(`usuário ${userId} está com CHAVE ALTERADA: confira /safety ${userId} e /trust ${userId} antes`);
    }
    this.approved.add(`${room}:${userId}`);
    await this.deliverTo(room, res.version, (await this.roomKeysFor(room))[res.version], pending);
  }

  // --- mensagens ------------------------------------------------------------

  async encrypt(room, cid, text) {
    const version = this.currentVersion.get(room);
    const keys = await this.roomKeysFor(room);
    return e2ee.encryptMessage({ roomKey: keys[version], kv: version, roomId: room, senderId: this.me.id, cid, text, senderEcdsaKey: this.identity.ecdsa.privateKey });
  }

  // Mensagem que não verifica pode ser de quem trocou de chave: confere o
  // diretório de novo (aviso de CHAVE ALTERADA) antes de só descartar.
  async accept(packet) {
    const result = await this.receiver.accept(packet);
    if (result.status === "invalid" && packet.from !== this.me.id && (await this.observe(packet.from)) === "CHANGED") {
      return { status: "untrusted", trust: "changed" };
    }
    return result;
  }
}

module.exports = { E2eeSession, clean };
