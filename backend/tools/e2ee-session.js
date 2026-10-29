// Estado E2EE do cliente de referência (docs/05-e2ee.md): keystore cifrado
// (identidade + chaves de sala recebidas), trust store (TOFU), registro das
// chaves no diretório, chave da sala (criar, receber, entregar) e mensagens.
//
// `api(method, path, body)` faz a requisição autenticada e devolve
// { status, body }. Nada aqui imprime segredos: só ids, fingerprints e
// estados.
const fs = require("node:fs");
const e2ee = require("../../shared/e2ee");
const files = require("../../shared/e2ee/node");

// Texto vindo de outros usuários ou do servidor (mensagens, nomes, códigos)
// é impresso com os caracteres de controle VISÍVEIS (\u001b...): sem isso,
// uma mensagem com sequências de escape ANSI poderia apagar a tela, mudar o
// título do terminal ou forjar linhas como "[verificado]".
const clean = (value) =>
  String(value).replace(/[\u0000-\u001f\u007f-\u009f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);

const ok = (res, ...statuses) => {
  if (res.parseError) throw new Error(`resposta do servidor não é JSON (status ${res.status})`);
  if (!statuses.includes(res.status)) throw new Error(`resposta inesperada do servidor (${res.status})`);
  return res.body;
};

// Estado (keystore e trust store) só muda na memória DEPOIS de gravado no
// disco: se a gravação falhar, nada fica "valendo só nesta sessão" (um pin
// que sumiria no reinício, uma confirmação que o usuário viu falhar).

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
    if (fs.existsSync(this.keystorePath)) {
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
    this.trust = fs.existsSync(this.trustPath)
      ? await files.readSealedFile(this.trustPath, this.passphrase)
      : e2ee.emptyTrustStore();
  }

  async save(data = this.data) {
    await files.writeSealedFile(this.keystorePath, this.passphrase, data);
    this.data = data;
  }

  async saveTrust(store = this.trust) {
    await files.writeSealedFile(this.trustPath, this.passphrase, store);
    this.trust = store;
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
    await this.save({ ...this.data, roomKeys: {} }); // os wraps antigos foram apagados no servidor
    this.print(`chaves substituídas no servidor (key_epoch ${this.keyEpoch})`);
  }

  // --- trust store ---------------------------------------------------------

  // Busca a chave do usuário no diretório e passa pelo TOFU. Devolve o
  // status (PINNED, MATCH, CHANGED) ou null se ele não tem chave.
  async observe(userId, keys) {
    let pub = keys;
    if (!pub) {
      const res = await this.api("get", `/keys/${userId}`);
      if (res.status === 404 && !res.parseError) return null;
      pub = ok(res, 200);
    }
    const r = await e2ee.observeKeys(this.trust, userId, pub);
    if (r.status !== "MATCH") await this.saveTrust(r.store);
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
    await this.saveTrust(e2ee.confirmTrust(this.trust, userId, shown));
    this.shownFingerprint.delete(userId);
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

  // Guarda a chave da sala e o que fica fixado da sala (criador e maior
  // versão) numa gravação só.
  async storeRoomKey(room, version, roomKey, pin) {
    const raw = e2ee.encoding.toB64url(await e2ee.primitives.exportRaw(roomKey));
    await this.save({
      ...this.data,
      roomKeys: { ...this.data.roomKeys, [room]: { ...this.data.roomKeys[room], [version]: raw } },
      rooms: { ...this.data.rooms, [room]: pin },
    });
  }

  async createRoom(name) {
    const created = ok(await this.api("post", "/createRoom", { name }), 201);
    const roomKey = await e2ee.generateRoomKey();
    const ctx = { roomId: created.id, version: 1 };
    const wrap = await e2ee.wrapRoomKey({ ...ctx, roomKey, senderId: this.me.id, recipientId: this.me.id, recipientEcdhPub: this.pub.ecdhPub, senderEcdsaKey: this.identity.ecdsa.privateKey });
    const commitment = await e2ee.commitRoomKey({ ...ctx, roomKey, creatorEcdsaKey: this.identity.ecdsa.privateKey });
    ok(await this.api("post", `/rooms/${created.id}/keys`, { version: 1, wrap, ...commitment }), 201);
    await this.storeRoomKey(created.id, 1, roomKey, { creator: this.me.id, version: 1 });
    this.currentVersion.set(created.id, 1);
    return created;
  }

  // Garante a chave atual da sala e abre as versões que ainda não tem (o
  // histórico de antes de uma rotação continua legível). Cada wrap é
  // conferido com as chaves FIXADAS: assinatura do remetente e compromisso
  // do autor da versão (o criador, na v1; quem rotacionou, nas seguintes).
  // O criador da v1 e a maior versão vista de cada sala ficam FIXADOS no
  // keystore: o servidor não pode, depois, apresentar outro "criador" nem
  // voltar versão. Devolve { ok, sender } (sender = quem entregou a chave
  // atual, para mostrar a confiança).
  async ensureRoomKey(room) {
    const state = ok(await this.api("get", `/rooms/${room}/keys`), 200);
    const pinned = this.data.rooms[room];
    if (pinned && state.currentVersion < pinned.version) {
      this.print(`! o servidor informa a versão ${state.currentVersion} da chave da sala ${room}, menor que a já vista (${pinned.version}): recusada`);
      return { ok: false };
    }
    this.currentVersion.set(room, state.currentVersion);
    if (this.hasCurrentKey(room)) return { ok: true };
    const missing = state.wraps
      .filter((w) => w.version <= state.currentVersion && !this.data.roomKeys[room]?.[w.version])
      .sort((a, b) => a.version - b.version);
    let sender;
    for (const wrap of missing) {
      if ((await this.openWrap(room, state, wrap)) && wrap.version === state.currentVersion) sender = wrap.senderId;
    }
    return this.hasCurrentKey(room) ? { ok: true, sender } : { ok: false };
  }

  // Abre e guarda UM wrap. false (com aviso) se não conferir; um wrap da
  // versão atual que não confere é descartado no servidor (outro membro
  // pode entregar um bom).
  async openWrap(room, state, wrap) {
    const info = state.versions.find((v) => v.version === wrap.version);
    if (!info) return false;
    const pinned = this.data.rooms[room];
    if (wrap.version === 1 && pinned?.creator !== undefined && pinned.creator !== info.createdBy) {
      this.print(`! o criador da sala ${room} informado pelo servidor mudou (era usuário ${pinned.creator}, agora ${clean(info.createdBy)}): chave recusada`);
      return false;
    }
    const sender = await this.senderKeyFor(wrap.senderId);
    const author = await this.senderKeyFor(info.createdBy);
    if (!["verified", "unverified"].includes(sender.trust) || !["verified", "unverified"].includes(author.trust)) {
      this.print(`! a chave v${wrap.version} da sala ${room} veio de quem tem chave não confiável (usuário ${clean(wrap.senderId)}); não aceita`);
      return false;
    }
    // Só a CRIPTOGRAFIA fica no try: um erro local (disco cheio, permissão)
    // sobe como erro — tratá-lo como "wrap inválido" apagaria um wrap bom.
    let roomKey;
    try {
      roomKey = await e2ee.unwrapRoomKey({ wrap, roomId: room, version: wrap.version, senderId: wrap.senderId, recipientId: this.me.id, recipientEcdhKey: this.identity.ecdh.privateKey, senderEcdsaPub: sender.ecdsaPub });
      await e2ee.verifyRoomKeyCommitment({ roomKey, roomId: room, version: wrap.version, commitment: info.commitment, commitmentSig: info.commitmentSig, creatorEcdsaPub: author.ecdsaPub });
      // A chave de uma versão nova é aleatória (D4): repetir a de outra
      // versão é um membro (ou cliente com bug) reaproveitando a chave que
      // quem saiu ainda tem.
      const raw = e2ee.encoding.toB64url(await e2ee.primitives.exportRaw(roomKey));
      if (Object.values(this.data.roomKeys[room] ?? {}).includes(raw)) {
        throw new e2ee.E2eeError("KEY_REUSED", "a chave nova repete a de outra versão");
      }
    } catch (err) {
      if (!(err instanceof e2ee.E2eeError)) throw err;
      if (wrap.version !== state.currentVersion) {
        this.print(`! a chave v${wrap.version} da sala ${room} não confere (${err.code}); o histórico dessa versão fica ilegível`);
        return false;
      }
      const discarded = await this.api("delete", `/rooms/${room}/keys/wraps/mine`);
      this.print(
        `! a chave recebida para a sala ${room} não confere (${err.code}); ` +
          (discarded.status === 204 ? "wrap descartado, aguardando outro" : `o descarte do wrap falhou (${discarded.status})`)
      );
      return false;
    }
    const creator = pinned?.creator ?? (wrap.version === 1 ? info.createdBy : undefined);
    await this.storeRoomKey(room, wrap.version, roomKey, { creator, version: Math.max(wrap.version, pinned?.version ?? 0) });
    return true;
  }

  async pendingOf(room) {
    const res = await this.api("get", `/rooms/${room}/keys/pending`);
    if (res.status === 403) throw new Error(`o servidor não reconhece sua chave atual da sala ${room}: não dá para consultar os pendentes (403)`);
    return ok(res, 200);
  }

  // Falha na entrega é sempre AVISADA (o pendente ficaria esperando para
  // sempre sem que ninguém soubesse).
  async deliverTo(room, version, roomKey, pending) {
    const wrap = await e2ee.wrapRoomKey({ roomKey, roomId: room, version, senderId: this.me.id, recipientId: pending.userId, recipientEcdhPub: pending.keys.ecdhPub, senderEcdsaKey: this.identity.ecdsa.privateKey });
    const posted = await this.api("post", `/rooms/${room}/keys/wraps`, { version, recipientId: pending.userId, recipientKeyEpoch: pending.keys.keyEpoch, wrap });
    if (posted.status === 201) {
      this.print(`chave da sala entregue a usuário ${pending.userId} (${clean(pending.name)})`);
      return;
    }
    const hint = posted.status === 409 ? "; as chaves dele podem ter mudado: confira /members e /safety" : "";
    throw new Error(`não foi possível entregar a chave da sala a usuário ${pending.userId} (${posted.status})${hint}`);
  }

  // Pendentes: a chave pública de cada um é conferida no trust store (CHAVE
  // ALTERADA → nunca entrega). Entrega automática só a quem foi VERIFICADO
  // ou aprovado (/approve); os demais são anunciados uma vez, com a
  // fingerprint, para o usuário decidir.
  async distribute(room) {
    if (!this.hasCurrentKey(room)) return;
    const res = await this.pendingOf(room);
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
            // Fingerprint calculada AQUI a partir das chaves (a do servidor não é confiável).
            `fingerprint ${this.trust.peers[pending.userId].fingerprint.slice(0, 16)} [${this.trustLabel(pending.userId)}]. ` +
            `Se você espera essa pessoa na sala: confira /safety ${pending.userId} e entregue com /approve ${pending.userId}`
        );
      }
    }
  }

  // O usuário aprova a entrega da chave da sala a um pendente específico.
  async approve(room, userId) {
    if (!this.hasCurrentKey(room)) throw new Error("você ainda não tem a chave desta sala");
    const res = await this.pendingOf(room);
    const pending = res.pending.find((p) => p.userId === userId);
    if (!pending) throw new Error(`usuário ${userId} não está aguardando a chave da sala ${room}`);
    if (!pending.keys) throw new Error(`usuário ${userId} ainda não registrou chaves públicas`);
    await this.observe(userId, pending.keys);
    if (e2ee.trustState(this.trust, userId, pending.keys) === "changed") {
      throw new Error(`usuário ${userId} está com CHAVE ALTERADA: confira /safety ${userId} e /trust ${userId} antes`);
    }
    this.approved.add(`${room}:${userId}`);
    await this.deliverTo(room, res.version, (await this.roomKeysFor(room))[res.version], pending);
  }

  // --- composição da sala e rotação (Etapa 4b-2) ----------------------------

  // Membros que entram numa rotação: o próprio usuário e quem tem a chave
  // pública fixada e VERIFICADA, ou foi aprovado (/approve) nesta sala — a
  // mesma regra da entrega. Os demais (não verificados, CHAVE ALTERADA, sem
  // chave) ficam de fora e voltam a ser pendentes: o servidor decide quem é
  // membro e poderia inserir uma conta para receber a chave nova.
  async rotationRecipients(room) {
    const members = ok(await this.api("get", `/roomUsers/${room}`), 200);
    const recipients = [{ userId: this.me.id, keyEpoch: this.keyEpoch, ecdhPub: this.pub.ecdhPub }];
    const left = [];
    for (const member of members) {
      if (member.id === this.me.id) continue;
      const res = await this.api("get", `/keys/${member.id}`);
      if (res.status === 404 && !res.parseError) {
        left.push(member.id);
        continue;
      }
      const keys = ok(res, 200);
      await this.observe(member.id, keys);
      const state = e2ee.trustState(this.trust, member.id, keys);
      if (state === "verified" || (state === "unverified" && this.approved.has(`${room}:${member.id}`))) {
        recipients.push({ userId: member.id, keyEpoch: keys.keyEpoch, ecdhPub: keys.ecdhPub });
      } else {
        left.push(member.id);
      }
    }
    return { recipients, left };
  }

  // Troca a chave da sala: chave NOVA de getRandomValues (nunca derivada da
  // anterior: quem saiu a calcularia), compromisso assinado por mim e um
  // wrap por destinatário. 409 STALE_MEMBERSHIP (alguém saiu ou trocou de
  // chave no meio) → monta de novo, até `attempts` vezes. 409 de versão =
  // outro membro rotacionou antes: busca a chave dele e para.
  // Devolve { rotated, version, left } ou { rotated: false, reason }.
  async rotate(room, { attempts = 3 } = {}) {
    const got = await this.ensureRoomKey(room);
    if (!got.ok) throw new Error(`você não tem a chave atual da sala ${room}: não dá para trocá-la`);
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const version = this.currentVersion.get(room) + 1;
      const { recipients, left } = await this.rotationRecipients(room);
      const roomKey = await e2ee.generateRoomKey();
      const ctx = { roomId: room, version };
      const commitment = await e2ee.commitRoomKey({ ...ctx, roomKey, creatorEcdsaKey: this.identity.ecdsa.privateKey });
      const wraps = [];
      for (const r of recipients) {
        const wrap = await e2ee.wrapRoomKey({ ...ctx, roomKey, senderId: this.me.id, recipientId: r.userId, recipientEcdhPub: r.ecdhPub, senderEcdsaKey: this.identity.ecdsa.privateKey });
        wraps.push({ recipientId: r.userId, recipientKeyEpoch: r.keyEpoch, wrap });
      }
      const res = await this.api("post", `/rooms/${room}/keys/rotate`, { version, ...commitment, wraps });
      if (res.status === 201 && !res.parseError) {
        const pinned = this.data.rooms[room];
        await this.storeRoomKey(room, version, roomKey, { creator: pinned?.creator, version });
        this.currentVersion.set(room, version);
        return { rotated: true, version, left };
      }
      if (res.status === 409 && res.body?.code === "STALE_MEMBERSHIP") continue;
      if (res.status === 409) {
        await this.ensureRoomKey(room);
        return { rotated: false, reason: "concurrent" };
      }
      throw new Error(`o servidor recusou a troca da chave da sala ${room} (${res.status})`);
    }
    return { rotated: false, reason: "stale" };
  }

  // ROTATION_PENDING: quem tem a chave atual tenta rotacionar depois de um
  // atraso aleatório de 0 a `maxDelayMs` (reduz a colisão entre membros).
  // Se, depois do atraso, a versão já subiu, outro membro rotacionou.
  async autoRotate(room, { maxDelayMs = 2000 } = {}) {
    const seen = this.currentVersion.get(room);
    if (!this.hasCurrentKey(room)) return { rotated: false, reason: "no-key" };
    const [hi, lo] = e2ee.primitives.randomBytes(2);
    const delay = Math.floor((((hi << 8) | lo) / 65536) * maxDelayMs);
    await new Promise((resolve) => setTimeout(resolve, delay));
    await this.ensureRoomKey(room);
    if (this.currentVersion.get(room) !== seen) return { rotated: false, reason: "concurrent" };
    return this.rotate(room);
  }

  async leave(room) {
    const res = await this.api("post", `/rooms/${room}/leave`);
    if (res.status === 409 && res.body?.code === "OWNER_MUST_TRANSFER") {
      throw new Error("você é o dono e há outros membros: transfira o cargo antes (/owner <userId>)");
    }
    return ok(res, 200);
  }

  // Remover e trocar a chave em sequência (/kick): sem a rotação, o removido
  // leria com a chave que já tem tudo o que viesse depois — por isso o
  // servidor bloqueia o envio até a troca. Devolve o convite novo (uma vez).
  async kick(room, userId) {
    const removed = ok(await this.api("delete", `/rooms/${room}/members/${userId}`), 200);
    return { invite: removed.invite, rotation: await this.rotate(room) };
  }

  async transferOwner(room, userId) {
    return ok(await this.api("post", `/rooms/${room}/owner`, { userId }), 200);
  }

  async rotateInvite(room) {
    return ok(await this.api("post", `/rooms/${room}/invite/rotate`), 200).invite;
  }

  // --- mensagens ------------------------------------------------------------

  async encrypt(room, cid, text) {
    const version = this.currentVersion.get(room);
    const keys = await this.roomKeysFor(room);
    return e2ee.encryptMessage({ roomKey: keys[version], kv: version, roomId: room, senderId: this.me.id, cid, text, senderEcdsaKey: this.identity.ecdsa.privateKey });
  }

  // Mensagem que não verifica pode ser de quem trocou de chave: confere o
  // diretório de novo (aviso de CHAVE ALTERADA) antes de só descartar.
  // Envelope com kv MAIOR que o conhecido: a chave foi trocada e o wrap
  // pode já estar no servidor; busca e tenta de novo (senão, "sem chave").
  async accept(packet) {
    let result = await this.receiver.accept(packet);
    if (result.status === "missing_key" && result.kv > (this.currentVersion.get(packet.room) ?? 0)) {
      await this.ensureRoomKey(packet.room);
      result = await this.receiver.accept(packet);
    }
    if (result.status === "invalid" && packet.from !== this.me.id && (await this.observe(packet.from)) === "CHANGED") {
      return { status: "untrusted", trust: "changed" };
    }
    return result;
  }
}

module.exports = { E2eeSession, clean };
