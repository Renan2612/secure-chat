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
    this.rotationRequired = new Map(); // sala → o servidor exige a troca da chave
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
  //
  // P1: o keystore guarda o identificador do SEU trust store (trustStoreId).
  // Trust store ausente com keystore existente (apagado, backup parcial,
  // outra máquina) → aviso claro e TOFU reiniciado: todas as chaves voltam a
  // ser não verificadas e precisam de /safety + /trust de novo. Trust store
  // com outro identificador (de outro keystore) → recusa, sem sobrescrever.
  async open() {
    const fresh = !fs.existsSync(this.keystorePath);
    if (fresh) {
      const identity = await e2ee.generateIdentity();
      this.data = { v: 1, userId: this.me.id, email: this.email, identity: await e2ee.exportIdentity(identity), roomKeys: {}, rooms: {} };
    } else {
      this.data = await files.readSealedFile(this.keystorePath, this.passphrase);
      if (this.data.userId !== this.me.id) {
        throw new Error(`o keystore ${this.keystorePath} é de outro usuário (${this.data.userId}); use --keystore`);
      }
    }
    this.data.rooms = this.data.rooms ?? {}; // sala → { creator, version } fixados (TOFU por sala)
    this.identity = await e2ee.importIdentity(this.data.identity);
    this.pub = await e2ee.exportPublicKeys(this.identity);
    await this.openTrust(fresh);
    if (fresh) this.print(`keystore novo criado em ${this.keystorePath} (sem recuperação: guarde o arquivo e a senha de cifragem)`);
  }

  async openTrust(fresh) {
    const newId = () => e2ee.encoding.toB64url(e2ee.primitives.randomBytes(16));
    const known = this.data.trustStoreId;
    if (fresh && fs.existsSync(this.trustPath)) {
      throw new Error(`já existe um trust store em ${this.trustPath} sem o keystore correspondente; mova-o ou use outro --keystore (nada foi alterado)`);
    }
    if (!fresh && fs.existsSync(this.trustPath)) {
      const trust = await files.readSealedFile(this.trustPath, this.passphrase);
      if (known && trust.id !== known) {
        throw new Error(`o trust store ${this.trustPath} não pertence a este keystore (identificador diferente); nada foi alterado`);
      }
      if (known) {
        this.trust = trust;
        return;
      }
      // Keystore da 4b-1, sem identificador: adota (ou cria) o do trust store.
      // O trust store é gravado primeiro: se a gravação do keystore falhar,
      // a próxima abertura adota o mesmo identificador.
      const id = trust.id ?? newId();
      await this.saveTrust({ ...trust, id });
      await this.save({ ...this.data, trustStoreId: id });
      return;
    }
    if (!fresh) {
      this.trustReset = true;
      this.print(
        `! ATENÇÃO: o trust store ${this.trustPath} não foi encontrado, mas o keystore existe. ` +
          "TOFU reiniciado: as chaves de TODOS os outros usuários voltam a ser NÃO VERIFICADAS. " +
          "Confira de novo cada pessoa com /safety <id> e confirme com /trust <id>. " +
          "Se você não apagou o arquivo, alguém pode ter mexido nesta máquina."
      );
    }
    // Keystore primeiro: se a gravação do trust store falhar, a próxima
    // abertura avisa de novo (nunca fica um trust store "aceito" sem aviso).
    const id = newId();
    await this.save({ ...this.data, trustStoreId: id });
    await this.saveTrust({ ...e2ee.emptyTrustStore(), id });
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

  // Etapa 5 (A3): o nome não vai em claro. A sala nasce sem nome e ele
  // chega cifrado com a v1 da chave (o AAD do nome precisa do id da sala).
  async createRoom(name) {
    const created = ok(await this.api("post", "/createRoom", {}), 201);
    const roomKey = await e2ee.generateRoomKey();
    const ctx = { roomId: created.id, version: 1 };
    const wrap = await e2ee.wrapRoomKey({ ...ctx, roomKey, senderId: this.me.id, recipientId: this.me.id, recipientEcdhPub: this.pub.ecdhPub, senderEcdsaKey: this.identity.ecdsa.privateKey });
    const commitment = await e2ee.commitRoomKey({ ...ctx, roomKey, creatorEcdsaKey: this.identity.ecdsa.privateKey });
    const nameEnv = await e2ee.encryptRoomName({ roomKey, roomId: created.id, kv: 1, name });
    ok(await this.api("post", `/rooms/${created.id}/keys`, { version: 1, wrap, ...commitment, nameEnv }), 201);
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
    this.rotationRequired.set(room, state.rotationRequired === true);
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

  // Quem este usuário removeu (/kick) de cada sala, guardado no keystore
  // cifrado: nunca volta a receber a chave (rotação ou entrega), nem depois
  // de reiniciar o cliente, mesmo que o servidor volte a listá-lo.
  isKicked(room, userId) {
    return (this.data.kicked?.[room] ?? []).includes(userId);
  }

  // Abre e guarda UM wrap. false (com aviso) se não conferir; um wrap da
  // versão atual que não confere é descartado no servidor (outro membro
  // pode entregar um bom).
  async openWrap(room, state, wrap) {
    const info = state.versions.find((v) => v.version === wrap.version);
    if (!info) {
      this.print(`! o servidor entregou um wrap da v${clean(wrap.version)} da sala ${room} sem o compromisso dessa versão: não aceito`);
      return false;
    }
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
    // Achado da revisão: a partir da v2, quem escolheu a chave é quem
    // rotacionou. Aceitar um autor só fixado por TOFU deixaria o servidor
    // inserir uma conta, "rotacionar" com uma chave dele e ler o que viesse
    // depois. Vale só o próprio usuário ou alguém VERIFICADO (/safety +
    // /trust). Um /approve não basta: ele vive só na memória e não acompanha
    // a saída da pessoa (ela poderia "rotacionar" depois de sair).
    if (wrap.version > 1 && info.createdBy !== this.me.id && author.trust !== "verified") {
      this.print(
        `! a chave v${wrap.version} da sala ${room} foi trocada por usuário ${clean(info.createdBy)}, que você não verificou: não aceita. ` +
          `Confira /safety ${clean(info.createdBy)} e confirme com /trust ${clean(info.createdBy)}`
      );
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
      if (this.isKicked(room, pending.userId)) continue;
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
    if (this.isKicked(room, userId)) throw new Error(`você removeu o usuário ${userId} desta sala: a chave não lhe é entregue`);
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
    // Aprovação de quem já não é membro deixa de valer: se voltar, precisa
    // de um /approve novo.
    const ids = new Set(members.map((m) => m.id));
    for (const key of [...this.approved]) {
      const [r, u] = key.split(":").map(Number);
      if (r === room && !ids.has(u)) this.approved.delete(key);
    }
    const recipients = [{ userId: this.me.id, keyEpoch: this.keyEpoch, ecdhPub: this.pub.ecdhPub }];
    const left = [];
    for (const member of members) {
      if (member.id === this.me.id) continue;
      if (this.isKicked(room, member.id)) {
        left.push(member.id);
        continue;
      }
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

  // --- ajustes da sala (Etapa 5) ----------------------------------------------

  // { name, retentionSeconds, ownerId } da sala, pelo GET /rooms. O nome é
  // decifrado com as chaves que este cliente tem; sem a chave (ou se não
  // conferir), name = null e quem exibe mostra "Sala #id".
  async roomInfo(room) {
    const rooms = ok(await this.api("get", "/rooms"), 200);
    const info = Array.isArray(rooms) ? rooms.find((r) => r.id === room) : undefined;
    if (!info) throw new Error(`a sala ${room} não aparece na sua lista`);
    let name = null;
    if (info.nameEnv) {
      try {
        name = await e2ee.decryptRoomName({ nameEnv: info.nameEnv, roomKeys: await this.roomKeysFor(room), roomId: room });
      } catch (err) {
        if (!(err instanceof e2ee.E2eeError)) throw err;
      }
    }
    return { name, retentionSeconds: info.retentionSeconds ?? null, ownerId: info.ownerId };
  }

  // Nome cifrado com a chave da versão `version` (a atual, ou a nova numa
  // rotação).
  nameEnvFor(room, version, roomKey, name) {
    return e2ee.encryptRoomName({ roomKey, roomId: room, kv: version, name });
  }

  async rename(room, name) {
    await this.ensureRoomKey(room);
    const version = this.currentVersion.get(room);
    const roomKey = (await this.roomKeysFor(room))[version];
    if (!roomKey) throw new Error(`você não tem a chave atual da sala ${room}`);
    const res = await this.api("put", `/rooms/${room}/name`, { nameEnv: await this.nameEnvFor(room, version, roomKey, name) });
    if (res.status === 403) throw new Error("só o dono da sala troca o nome");
    if (res.status === 409 && res.body?.code === "ROTATION_PENDING") throw new Error("a chave precisa ser trocada antes (alguém saiu)");
    return ok(res, 200);
  }

  async setRetention(room, retentionSeconds) {
    const res = await this.api("put", `/rooms/${room}/retention`, { retentionSeconds });
    if (res.status === 403) throw new Error("só o dono da sala define a retenção");
    if (res.status === 400) throw new Error("retenção inválida (de 60 s a 604800 s, ou off)");
    return ok(res, 200).retentionSeconds;
  }

  async bans(room) {
    const res = await this.api("get", `/rooms/${room}/bans`);
    if (res.status === 403) throw new Error("só o dono da sala vê os banimentos");
    return ok(res, 200).bans;
  }

  async unban(room, userId) {
    const res = await this.api("delete", `/rooms/${room}/bans/${userId}`);
    if (res.status === 403) throw new Error("só o dono da sala desfaz banimentos");
    if (res.status === 404) throw new Error(`usuário ${userId} não está banido desta sala`);
    if (res.status !== 204) throw new Error(`resposta inesperada do servidor (${res.status})`);
  }

  // Troca a chave da sala: chave NOVA de getRandomValues (nunca derivada da
  // anterior: quem saiu a calcularia), compromisso assinado por mim e um
  // wrap por destinatário. 409 STALE_MEMBERSHIP (alguém saiu ou trocou de
  // chave no meio) → monta de novo, até `attempts` vezes. 409 de versão =
  // outro membro rotacionou antes: busca a chave dele e para.
  // Devolve { rotated, version, left } ou { rotated: false, reason }.
  // `expectVersion` (rotação automática): se a versão já não é a que motivou
  // a rotação, outro membro rotacionou e não há o que fazer.
  async rotate(room, { attempts = 3, expectVersion } = {}) {
    const got = await this.ensureRoomKey(room);
    if (expectVersion !== undefined && this.currentVersion.get(room) !== expectVersion) return { rotated: false, reason: "concurrent" };
    if (!got.ok) throw new Error(`você não tem a chave atual da sala ${room}: não dá para trocá-la`);
    // Etapa 5: o nome vai recifrado com a chave nova (quem saiu não o lê).
    // Sem o nome atual legível, vai "Sala #id": a rotação não pode ficar
    // bloqueada por isso (é ela que tira o acesso de quem saiu).
    const name = (await this.roomInfo(room)).name ?? `Sala #${room}`;
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
      const nameEnv = await this.nameEnvFor(room, version, roomKey, name);
      const res = await this.api("post", `/rooms/${room}/keys/rotate`, { version, ...commitment, wraps, nameEnv });
      if (res.status === 201) {
        // A versão nova já existe no servidor: uma falha local aqui não pode
        // virar "o servidor recusou". O próprio wrap continua lá.
        try {
          const pinned = this.data.rooms[room];
          await this.storeRoomKey(room, version, roomKey, { creator: pinned?.creator, version });
        } catch (err) {
          throw new Error(`a chave da sala ${room} foi trocada (v${version}), mas não foi possível gravá-la no keystore (${err.message}); ela será lida do seu wrap ao reiniciar`);
        }
        this.currentVersion.set(room, version);
        this.rotationRequired.set(room, false);
        return { rotated: true, version, left };
      }
      if (res.status === 409 && res.body?.code === "STALE_MEMBERSHIP") continue;
      if (res.status === 409) {
        await this.ensureRoomKey(room);
        return { rotated: false, reason: "concurrent" };
      }
      const why = typeof res.body?.message === "string" ? `: ${clean(res.body.message)}` : "";
      throw new Error(`o servidor recusou a troca da chave da sala ${room} (${res.status}${why})`);
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
    return this.rotate(room, { expectVersion: seen });
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
    this.approved.delete(`${room}:${userId}`);
    // A remoção já valeu no servidor e o convite novo só vem nesta resposta:
    // nada abaixo pode fazê-lo sumir. Uma falha vira `rotationError`.
    try {
      const kicked = { ...this.data.kicked, [room]: [...new Set([...(this.data.kicked?.[room] ?? []), userId])] };
      await this.save({ ...this.data, kicked });
      return { invite: removed.invite, rotation: await this.rotate(room) };
    } catch (err) {
      return { invite: removed.invite, rotationError: err };
    }
  }

  async transferOwner(room, userId) {
    return ok(await this.api("post", `/rooms/${room}/owner`, { userId }), 200);
  }

  async rotateInvite(room) {
    return ok(await this.api("post", `/rooms/${room}/invite/rotate`), 200).invite;
  }

  // --- mensagens ------------------------------------------------------------

  // exp: segundos Unix (e2ee.expFor) ou null; vai assinado no envelope v2.
  async encrypt(room, cid, text, exp = null) {
    const version = this.currentVersion.get(room);
    const keys = await this.roomKeysFor(room);
    return e2ee.encryptMessage({ roomKey: keys[version], kv: version, roomId: room, senderId: this.me.id, cid, text, senderEcdsaKey: this.identity.ecdsa.privateKey, exp });
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
