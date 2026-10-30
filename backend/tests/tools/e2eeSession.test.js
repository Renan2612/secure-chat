// E2eeSession (o que o ws-client realmente usa) contra um "servidor" falso e
// malicioso: aqui o servidor pode mentir sobre chaves, wraps, versões e
// respostas, e a sessão precisa falhar FECHADO usando o que ela fixou.
const fs = require("fs");
const os = require("os");
const path = require("path");
const e2ee = require("../../../shared/e2ee");
const { E2eeSession } = require("../../tools/e2ee-session");

const PASS = "senha-de-cifragem-unit";

const newSession = async (routes, me = { id: 1 }) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "e2ee-session-"));
  const printed = [];
  const calls = [];
  const api = async (method, url, body) => {
    calls.push(`${method.toUpperCase()} ${url}`);
    const handler = routes[`${method.toUpperCase()} ${url}`];
    return handler ? handler(body) : { status: 404, body: { message: "Não encontrado" } };
  };
  const s = new E2eeSession({ api, me, email: "me@example.com", keystorePath: path.join(dir, "k.json"), passphrase: PASS, print: (l) => printed.push(l) });
  await s.open();
  return { s, printed, calls };
};

const identity = async () => {
  const id = await e2ee.generateIdentity();
  id.pub = await e2ee.exportPublicKeys(id);
  return id;
};

let alice;
let mallory;
let other;

beforeAll(async () => {
  alice = await identity();
  mallory = await identity();
  other = await identity();
});

// Wrap + compromisso para o "me" (userId 1), assinados por `signer` mas
// apresentados como vindos do usuário 2.
const roomStateFor = async (me, signer, { version = 1, roomKey } = {}) => {
  const key = roomKey ?? (await e2ee.generateRoomKey());
  const wrap = await e2ee.wrapRoomKey({ roomKey: key, roomId: 7, version, senderId: 2, recipientId: 1, recipientEcdhPub: me.pub.ecdhPub, senderEcdsaKey: signer.ecdsa.privateKey });
  const c = await e2ee.commitRoomKey({ roomId: 7, version, roomKey: key, creatorEcdsaKey: signer.ecdsa.privateKey });
  return { status: 200, body: { room: 7, currentVersion: version, versions: [{ version, createdBy: 2, ...c }], wraps: [{ version, senderId: 2, ...wrap }] } };
};

describe("chave da sala com servidor malicioso", () => {
  test("ataque: o servidor troca a chave da Alice no diretório E entrega wrap/compromisso da Mallory em nome dela → recusado (vale a chave FIXADA)", async () => {
    let directory = alice.pub; // primeiro o diretório é honesto
    const { s, printed, calls } = await newSession({
      "GET /keys/2": () => ({ status: 200, body: { ...directory, keyEpoch: 1 } }),
      "DELETE /rooms/7/keys/wraps/mine": () => ({ status: 204, body: null }),
    });
    s.pub = s.pub ?? (await e2ee.exportPublicKeys(s.identity));
    await s.observe(2); // fixa a chave verdadeira da Alice
    directory = mallory.pub; // o servidor passa a mentir
    const me = { pub: s.pub };
    const routes = await roomStateFor(me, mallory);
    s.api = async (m, u, b) => (`${m.toUpperCase()} ${u}` === "GET /rooms/7/keys" ? routes : (calls.push(`${m.toUpperCase()} ${u}`), u.endsWith("/mine") ? { status: 204 } : { status: 200, body: { ...directory, keyEpoch: 1 } }));
    expect(await s.ensureRoomKey(7)).toEqual({ ok: false });
    expect(s.hasCurrentKey(7)).toBe(false);
    expect(printed.join("\n")).toMatch(/não confere/);
    expect(calls).toContain("DELETE /rooms/7/keys/wraps/mine");
  });

  test("ataque: versão MENOR que a já vista é recusada (rollback)", async () => {
    const { s, printed } = await newSession({});
    s.data.rooms[7] = { creator: 2, version: 2 };
    s.api = async () => ({ status: 200, body: { room: 7, currentVersion: 1, versions: [], wraps: [] } });
    expect(await s.ensureRoomKey(7)).toEqual({ ok: false });
    expect(printed.join("\n")).toMatch(/menor que a já vista \(2\)/);
  });

  test("H1: erro de disco ao guardar a chave NÃO é tratado como wrap inválido nem apaga o wrap no servidor", async () => {
    const { s, calls } = await newSession({});
    const routes = await roomStateFor({ pub: s.pub }, alice);
    s.trust = (await e2ee.observeKeys(s.trust, 2, alice.pub)).store;
    s.api = async (m, u) => (calls.push(`${m.toUpperCase()} ${u}`), u === "/rooms/7/keys" ? routes : { status: 204 });
    s.save = async () => {
      throw Object.assign(new Error("sem espaço"), { code: "ENOSPC" });
    };
    await expect(s.ensureRoomKey(7)).rejects.toThrow(/sem espaço/);
    expect(calls).not.toContain("DELETE /rooms/7/keys/wraps/mine");
    expect(s.hasCurrentKey(7)).toBe(false); // nada ficou só na memória
    expect(s.data.rooms[7]).toBeUndefined();
  });
});

describe("trust store", () => {
  test("H2: se gravar o trust store falha, o pin NÃO fica só na memória", async () => {
    const { s } = await newSession({ "GET /keys/2": () => ({ status: 200, body: { ...alice.pub, keyEpoch: 1 } }) });
    s.saveTrust = async () => {
      throw new Error("disco cheio");
    };
    await expect(s.observe(2)).rejects.toThrow(/disco cheio/);
    expect(s.trust.peers[2]).toBeUndefined();
  });

  test("H2: /trust que não consegue gravar não deixa o usuário verificado", async () => {
    const { s } = await newSession({ "GET /keys/2": () => ({ status: 200, body: { ...alice.pub, keyEpoch: 1 } }) });
    await s.safety(2);
    s.saveTrust = async () => {
      throw new Error("disco cheio");
    };
    await expect(s.confirm(2)).rejects.toThrow(/disco cheio/);
    expect(s.trustLabel(2)).toBe("não verificado");
  });

  test("corrida do /trust: a chave muda depois do /safety → confirmação recusada e continua CHAVE ALTERADA", async () => {
    let directory = alice.pub;
    const { s } = await newSession({ "GET /keys/2": () => ({ status: 200, body: { ...directory, keyEpoch: 1 } }) });
    await s.observe(2);
    directory = mallory.pub;
    await s.observe(2); // CHANGED (mallory)
    await s.safety(2); // o usuário vê o número com a chave da mallory
    await s.observe(2, other.pub); // o servidor troca de novo
    await expect(s.confirm(2)).rejects.toThrow(/fingerprint/);
    expect(s.trustLabel(2)).toBe("CHAVE ALTERADA");
  });

  test("troca silenciosa de chave (sem reset, sem aviso) é detectada pela mensagem → CHAVE ALTERADA, nunca exibida", async () => {
    let directory = alice.pub;
    const { s } = await newSession({ "GET /keys/2": () => ({ status: 200, body: { ...directory, keyEpoch: 1 } }) });
    const roomKey = await e2ee.generateRoomKey();
    s.data.roomKeys[7] = { 1: e2ee.encoding.toB64url(await e2ee.primitives.exportRaw(roomKey)) };
    await s.observe(2); // fixa a Alice
    directory = mallory.pub; // admin troca user_keys direto no banco
    const body = await e2ee.encryptMessage({ roomKey, kv: 1, roomId: 7, senderId: 2, cid: "c", text: "sou a alice", senderEcdsaKey: mallory.ecdsa.privateKey });
    expect(await s.accept({ room: 7, from: 2, cid: "c", body })).toEqual({ status: "untrusted", trust: "changed" });
  });
});

describe("registro das próprias chaves", () => {
  test("ataque: o servidor apresenta OUTRAS chaves como sendo minhas → recusa (sem --reset-keys)", async () => {
    const { s } = await newSession({ "GET /keys/1": () => ({ status: 200, body: { ...mallory.pub, keyEpoch: 1 } }) });
    await expect(s.registerKeys()).rejects.toThrow(/--reset-keys/);
  });

  test("--reset-keys substitui no servidor e descarta as chaves de sala locais", async () => {
    const posted = [];
    const { s } = await newSession({
      "GET /keys/1": () => ({ status: 200, body: { ...mallory.pub, keyEpoch: 1 } }),
      "POST /keys/reset": (b) => (posted.push(b), { status: 200, body: { ...b, keyEpoch: 2 } }),
    });
    s.data.roomKeys[7] = { 1: "x" };
    await s.registerKeys({ reset: true });
    expect(posted).toEqual([s.pub]);
    expect(s.keyEpoch).toBe(2);
    expect(s.data.roomKeys).toEqual({});
  });

  test("M9: resposta que não é JSON vira erro claro (não um TypeError)", async () => {
    const { s } = await newSession({ "GET /keys/1": () => ({ status: 200, body: null, parseError: true }) });
    await expect(s.registerKeys()).rejects.toThrow(/não é JSON/);
  });
});

describe("entrega da chave da sala", () => {
  const withKey = async (routes) => {
    const r = await newSession(routes);
    const roomKey = await e2ee.generateRoomKey();
    r.s.data.roomKeys[7] = { 1: e2ee.encoding.toB64url(await e2ee.primitives.exportRaw(roomKey)) };
    r.s.currentVersion.set(7, 1);
    return r;
  };
  const pending = () => ({ status: 200, body: { room: 7, version: 1, pending: [{ userId: 3, name: "bob", keys: { ...other.pub, keyEpoch: 1 } }] } });

  test("H3: /approve com o servidor recusando o wrap é AVISADO (não some calado)", async () => {
    const { s, printed } = await withKey({
      "GET /rooms/7/keys/pending": () => pending(),
      "POST /rooms/7/keys/wraps": () => ({ status: 409, body: { message: "As chaves do destinatário mudaram" } }),
    });
    await expect(s.approve(7, 3)).rejects.toThrow(/não foi possível entregar.*409/);
    expect(printed.join("\n")).not.toMatch(/entregue a usuário/);
  });

  test("H3: pendentes que o servidor nega (403) dão erro claro, não 'não está aguardando'", async () => {
    const { s } = await withKey({ "GET /rooms/7/keys/pending": () => ({ status: 403, body: { message: "Acesso negado" } }) });
    await expect(s.approve(7, 3)).rejects.toThrow(/pendentes.*403/);
  });
});

describe("P1: trust store ausente com keystore existente", () => {
  const files = require("../../../shared/e2ee/node");
  const reopen = async (keystorePath) => {
    const printed = [];
    const s = new E2eeSession({ api: async () => ({ status: 404, body: {} }), me: { id: 1 }, email: "me@example.com", keystorePath, passphrase: PASS, print: (l) => printed.push(l) });
    await s.open();
    return { s, printed };
  };

  test("keystore novo já nasce com o trust store e o mesmo identificador nos dois", async () => {
    const { s } = await newSession({});
    expect(fs.existsSync(s.trustPath)).toBe(true);
    const trust = await files.readSealedFile(s.trustPath, PASS);
    expect(s.data.trustStoreId).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(trust.id).toBe(s.data.trustStoreId);
  });

  test("ataque/acidente: o trust store some → aviso claro, TODAS as chaves voltam a não verificadas (TOFU reiniciado)", async () => {
    const { s } = await newSession({ "GET /keys/2": () => ({ status: 200, body: { ...alice.pub, keyEpoch: 1 } }) });
    await s.observe(2);
    await s.safety(2);
    await s.confirm(2);
    expect(s.trustLabel(2)).toBe("verificado");
    const oldId = s.data.trustStoreId;
    fs.rmSync(s.trustPath);
    const { s: again, printed } = await reopen(s.keystorePath);
    expect(printed.join("\n")).toMatch(/trust store .* não foi encontrado.*NÃO VERIFICADAS/s);
    expect(again.trustReset).toBe(true);
    expect(again.trustLabel(2)).toBe("desconhecido");
    again.api = async () => ({ status: 200, body: { ...alice.pub, keyEpoch: 1 } });
    await again.observe(2);
    expect(again.trustLabel(2)).toBe("não verificado"); // exige reconfirmação
    // O identificador muda: o trust store antigo, se reaparecer, não vale mais.
    expect(again.data.trustStoreId).not.toBe(oldId);
    expect((await files.readSealedFile(again.trustPath, PASS)).id).toBe(again.data.trustStoreId);
    // Na abertura seguinte, sem aviso.
    expect((await reopen(s.keystorePath)).printed.join("\n")).not.toMatch(/não foi encontrado/);
  });

  test("trust store de OUTRO keystore no lugar → recusa abrir e não sobrescreve nada", async () => {
    const { s } = await newSession({});
    const foreign = { ...e2ee.emptyTrustStore(), id: "outro-id-qualquer-0000", peers: { 9: { forged: true } } };
    await files.writeSealedFile(s.trustPath, PASS, foreign);
    await expect(reopen(s.keystorePath)).rejects.toThrow(/não pertence a este keystore/);
    expect(await files.readSealedFile(s.trustPath, PASS)).toEqual(foreign);
  });

  test("keystore e trust store da 4b-1 (sem identificador) são migrados sem aviso, mantendo os pins", async () => {
    const { s } = await newSession({});
    const { trustStoreId, ...legacy } = s.data;
    await files.writeSealedFile(s.keystorePath, PASS, legacy);
    await files.writeSealedFile(s.trustPath, PASS, { v: 1, peers: { 2: { ...alice.pub, verified: true, fingerprint: "x" } } });
    const { s: again, printed } = await reopen(s.keystorePath);
    expect(printed.join("\n")).not.toMatch(/não foi encontrado/);
    expect(again.trustLabel(2)).toBe("verificado");
    expect(again.data.trustStoreId).toBeTruthy();
    expect((await files.readSealedFile(again.trustPath, PASS)).id).toBe(again.data.trustStoreId);
  });

  test("o trust store ANTIGO que reaparece depois do TOFU reiniciado não vale mais (recusa)", async () => {
    const { s } = await newSession({});
    const copy = `${s.trustPath}.copia`;
    fs.copyFileSync(s.trustPath, copy);
    fs.rmSync(s.trustPath);
    await reopen(s.keystorePath); // TOFU reiniciado, identificador novo
    fs.copyFileSync(copy, s.trustPath);
    await expect(reopen(s.keystorePath)).rejects.toThrow(/não pertence a este keystore/);
  });

  test("keystore novo num caminho onde já existe um trust store → recusa, sem sobrescrever", async () => {
    const { s } = await newSession({});
    const before = fs.readFileSync(s.trustPath, "utf8");
    fs.rmSync(s.keystorePath);
    await expect(reopen(s.keystorePath)).rejects.toThrow(/já existe um trust store/);
    expect(fs.readFileSync(s.trustPath, "utf8")).toBe(before);
    expect(fs.existsSync(s.keystorePath)).toBe(false);
  });
});
