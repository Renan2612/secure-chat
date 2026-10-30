// Rotação da chave no CLIENTE (E2eeSession, o que o ws-client usa), contra o
// servidor real (Etapa 4b-2, D4). Provas criptográficas:
//   - o removido, com todas as chaves antigas e todos os pacotes da versão
//     nova capturados, não decifra nada novo;
//   - o servidor insere uma conta nova na sala e o cliente não a inclui na
//     rotação sem /approve;
//   - o servidor (ou um membro) reapresenta wraps ou a chave antiga como se
//     fossem a versão nova, e o cliente rejeita.
const fs = require("fs");
const os = require("os");
const path = require("path");
const e2ee = require("../../../shared/e2ee");
const { E2eeSession } = require("../../tools/e2ee-session");
const { pool, resetDb } = require("../helpers");
const { startServer, loginUser } = require("../ws/helpers");

const PASS = "senha-de-cifragem-rotacao";

let srv;

// Sessão de verdade, falando HTTP com o servidor de teste pelo cookie.
const sessionFor = async (name) => {
  const user = await loginUser(srv, name);
  const api = async (method, url, body) => {
    let req = srv.http[method](url).set("Cookie", user.cookie);
    if (body) req = req.send(body);
    const res = await req;
    return { status: res.status, body: res.body };
  };
  const printed = [];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rotation-session-"));
  const s = new E2eeSession({ api, me: { id: user.id }, email: user.email, keystorePath: path.join(dir, "k.json"), passphrase: PASS, print: (l) => printed.push(l) });
  await s.open();
  await s.registerKeys();
  return Object.assign(s, { user, printed, id: user.id });
};

// O usuário confere e confirma a chave do outro (/safety + /trust).
const verify = async (s, other) => {
  await s.safety(other.id);
  await s.confirm(other.id);
};

const joinWith = async (s, room, invite) => {
  const res = await s.api("post", "/joinRooms", { idRoom: room, key: invite });
  if (res.status !== 200) throw new Error(`join: ${res.status}`);
};

const raw = async (key) => e2ee.encoding.toB64url(await e2ee.primitives.exportRaw(key));

// Mensagem cifrada por `s` gravada direto no banco (o canal /ws não importa aqui).
const storeMessage = async (s, room, text, cid) => {
  const body = await s.encrypt(room, cid, text);
  const kv = s.currentVersion.get(room);
  await pool.query("INSERT INTO messages (room, user_id, message, cid, key_version) VALUES ($1, $2, $3, $4, $5)", [room, s.id, body, cid, kv]);
  return { room, from: s.id, cid, body };
};

let alice;
let bob;
let carol;
let room;
let invite;

beforeEach(async () => {
  await resetDb();
  srv = await startServer();
  alice = await sessionFor("alice");
  bob = await sessionFor("bob");
  carol = await sessionFor("carol");
  const created = await alice.createRoom("Sala");
  room = created.id;
  invite = created.key;
  for (const s of [bob, carol]) {
    await joinWith(s, room, invite);
    await verify(alice, s);
    await verify(s, alice);
  }
  await alice.distribute(room); // verificados: entrega automática
  for (const s of [bob, carol]) expect((await s.ensureRoomKey(room)).ok).toBe(true);
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

test("/kick: remove, gera chave NOVA e rotaciona; quem ficou lê o novo e o antigo", async () => {
  const old = await storeMessage(carol, room, "antes da remoção", "antes");
  const { invite: fresh, rotation } = await alice.kick(room, bob.id);
  expect(fresh).toMatch(/^[0-9a-f]{32}$/);
  expect(rotation).toMatchObject({ rotated: true, version: 2 });
  expect((await carol.ensureRoomKey(room)).ok).toBe(true);
  expect(carol.currentVersion.get(room)).toBe(2);
  const keys = await carol.roomKeysFor(room);
  expect(await raw(keys[2])).not.toBe(await raw(keys[1]));
  const novo = await storeMessage(alice, room, "depois da remoção", "depois");
  expect(await carol.accept(novo)).toMatchObject({ status: "ok", text: "depois da remoção" });
  expect(await carol.accept(old)).toMatchObject({ status: "ok", text: "antes da remoção" });
});

test("ataque: o removido, com TODAS as chaves antigas e TODOS os pacotes da v2 capturados, não decifra nada novo", async () => {
  await alice.kick(room, bob.id);
  const msg = await storeMessage(alice, room, "segredo-pos-remocao", "seg");
  // Tudo o que um removido com acesso ao banco/rede da v2 poderia ter:
  const wraps = (await pool.query("SELECT * FROM room_key_wraps WHERE room = $1 AND version = 2", [room])).rows;
  const v2 = (await pool.query("SELECT * FROM room_key_versions WHERE room = $1 AND version = 2", [room])).rows[0];
  expect(wraps.map((w) => w.recipient_id).sort()).toEqual([alice.id, carol.id].sort());
  const bobKeys = await bob.roomKeysFor(room); // a v1, que ele já tinha
  expect(Object.keys(bobKeys)).toEqual(["1"]);
  // (1) nenhum wrap da v2 abre com a chave privada dele, em nome de ninguém.
  for (const w of wraps) {
    for (const recipientId of [bob.id, w.recipient_id]) {
      await expect(
        e2ee.unwrapRoomKey({
          wrap: { ephPub: w.eph_pub, iv: w.iv, wrapped: w.wrapped, sig: w.sig },
          roomId: room, version: 2, senderId: w.sender_id, recipientId,
          recipientEcdhKey: bob.identity.ecdh.privateKey, senderEcdsaPub: alice.pub.ecdsaPub,
        })
      ).rejects.toMatchObject({ code: "INVALID_WRAP" });
    }
  }
  // (2) a chave v1 não confere com o compromisso da v2 (não é a mesma).
  await expect(
    e2ee.verifyRoomKeyCommitment({ roomKey: bobKeys[1], roomId: room, version: 2, commitment: v2.commitment, commitmentSig: v2.commitment_sig, creatorEcdsaPub: alice.pub.ecdsaPub })
  ).rejects.toMatchObject({ code: "KEY_COMMITMENT_MISMATCH" });
  // (3) a mensagem v2 não decifra com nenhuma chave dele, nem com a v1 no lugar da v2.
  expect(await bob.receiver.accept(msg)).toMatchObject({ status: "missing_key", kv: 2 });
  await expect(
    e2ee.decryptMessage({ body: msg.body, roomKeys: { 2: bobKeys[1] }, roomId: room, senderId: alice.id, cid: "seg", senderEcdsaPub: alice.pub.ecdsaPub })
  ).rejects.toBeInstanceOf(e2ee.E2eeError);
  // (4) e o servidor já não lhe entrega nada.
  await expect(bob.ensureRoomKey(room)).rejects.toThrow(/403/);
});

test("ataque: o servidor insere uma conta nova na sala; o cliente NÃO a inclui na rotação sem /approve", async () => {
  const dave = await sessionFor("dave");
  await pool.query("INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)", [room, dave.id]);
  const { rotated, left } = await alice.rotate(room);
  expect(rotated).toBe(true);
  expect(left).toEqual([dave.id]);
  const v2 = (await pool.query("SELECT recipient_id FROM room_key_wraps WHERE room = $1 AND version = 2 ORDER BY recipient_id", [room])).rows;
  expect(v2.map((r) => r.recipient_id)).toEqual([alice.id, bob.id, carol.id].sort((a, b) => a - b));
  expect((await dave.ensureRoomKey(room)).ok).toBe(false);
  // Com /approve explícito, recebe a v2 (só a v2: o histórico não é retroativo).
  await alice.approve(room, dave.id);
  // A v2 foi escolhida pela Alice: o Dave só a aceita depois de verificá-la.
  expect((await dave.ensureRoomKey(room)).ok).toBe(false);
  await verify(dave, alice);
  expect((await dave.ensureRoomKey(room)).ok).toBe(true);
  expect(Object.keys(await dave.roomKeysFor(room))).toEqual(["2"]);
});

test("aprovado com /approve (não verificado) continua entrando nas rotações seguintes da mesma sessão", async () => {
  const dave = await sessionFor("dave");
  const { invite: fresh } = await alice.kick(room, bob.id);
  await joinWith(dave, room, fresh);
  await alice.approve(room, dave.id);
  expect((await alice.rotate(room)).rotated).toBe(true);
  expect((await pool.query("SELECT 1 FROM room_key_wraps WHERE room = $1 AND version = 3 AND recipient_id = $2", [room, dave.id])).rowCount).toBe(1);
});

describe("ataque: wraps ou chave antigos apresentados como a versão nova", () => {
  test("o servidor reapresenta o wrap e o compromisso da v1 como v2 → recusado, nada guardado", async () => {
    // Carol perde a v1 local para o servidor poder "reapresentá-la".
    await pool.query("UPDATE rooms SET key_version = 2 WHERE id = $1", [room]);
    await pool.query("INSERT INTO room_key_versions (room, version, created_by, commitment, commitment_sig) SELECT room, 2, created_by, commitment, commitment_sig FROM room_key_versions WHERE room = $1 AND version = 1", [room]);
    await pool.query(
      `INSERT INTO room_key_wraps (room, version, recipient_id, sender_id, recipient_key_epoch, eph_pub, iv, wrapped, sig)
       SELECT room, 2, recipient_id, sender_id, recipient_key_epoch, eph_pub, iv, wrapped, sig FROM room_key_wraps WHERE room = $1 AND version = 1 AND recipient_id = $2`,
      [room, carol.id]
    );
    expect(await carol.ensureRoomKey(room)).toEqual({ ok: false });
    expect(Object.keys(await carol.roomKeysFor(room))).toEqual(["1"]);
    expect(carol.printed.join("\n")).toMatch(/não confere \(INVALID_WRAP\)/);
  });

  test("um membro rotaciona REUSANDO a chave v1 (assinaturas válidas) → os outros recusam (KEY_REUSED)", async () => {
    const reused = (await alice.roomKeysFor(room))[1];
    const realGenerate = e2ee.generateRoomKey;
    e2ee.generateRoomKey = async () => reused; // cliente com bug/malicioso
    try {
      expect((await alice.rotate(room)).rotated).toBe(true);
    } finally {
      e2ee.generateRoomKey = realGenerate;
    }
    expect(await carol.ensureRoomKey(room)).toEqual({ ok: false });
    expect(carol.printed.join("\n")).toMatch(/KEY_REUSED/);
    expect(Object.keys(await carol.roomKeysFor(room))).toEqual(["1"]);
  });
});

test("mensagem com kv maior que o conhecido: o cliente busca o wrap da versão nova e decifra", async () => {
  await alice.kick(room, bob.id);
  const msg = await storeMessage(alice, room, "v2 chegando", "v2");
  expect(carol.currentVersion.get(room)).toBe(1); // ainda não viu a rotação
  expect(await carol.accept(msg)).toMatchObject({ status: "ok", text: "v2 chegando" });
});

test("kv maior e sem wrap para mim → missing_key (\"sem chave\"), nunca exibida", async () => {
  const dave = await sessionFor("dave");
  await pool.query("INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)", [room, dave.id]);
  await alice.rotate(room); // dave fica de fora
  const msg = await storeMessage(alice, room, "para os verificados", "x");
  expect(await dave.accept(msg)).toMatchObject({ status: "missing_key", kv: 2 });
});

test("rotação automática: dois membros recebem ROTATION_PENDING; só uma versão nova nasce e todos acabam com ela", async () => {
  await bob.leave(room);
  const results = await Promise.all([alice.autoRotate(room, { maxDelayMs: 50 }), carol.autoRotate(room, { maxDelayMs: 50 })]);
  expect(results.filter((r) => r.rotated)).toHaveLength(1);
  expect((await pool.query("SELECT version FROM room_key_versions WHERE room = $1 ORDER BY version", [room])).rows.map((r) => r.version)).toEqual([1, 2]);
  for (const s of [alice, carol]) {
    await s.ensureRoomKey(room);
    expect(s.hasCurrentKey(room)).toBe(true);
    expect(s.currentVersion.get(room)).toBe(2);
  }
});

test("quem não tem a chave atual não tenta rotacionar sozinho", async () => {
  const dave = await sessionFor("dave");
  await joinWith(dave, room, invite);
  expect(await dave.autoRotate(room, { maxDelayMs: 0 })).toEqual({ rotated: false, reason: "no-key" });
});

test("/leave do dono com outros membros: erro claro (transferir antes)", async () => {
  await expect(alice.leave(room)).rejects.toThrow(/transfira o cargo/);
  await alice.transferOwner(room, carol.id);
  expect((await alice.leave(room)).roomDeleted).toBe(false);
});

test("/invite devolve um convite novo, e o antigo deixa de valer", async () => {
  const fresh = await alice.rotateInvite(room);
  const dave = await sessionFor("dave");
  await expect(joinWith(dave, room, invite)).rejects.toThrow(/403/);
  await joinWith(dave, room, fresh);
});

describe("achados da revisão de segurança", () => {
  test("ataque: o servidor insere uma conta e 'rotaciona' em nome dela (autor só fixado por TOFU) → a chave nova não é aceita", async () => {
    const mallory = await sessionFor("mallory");
    await pool.query("INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)", [room, mallory.id]);
    // O servidor dá a Mallory a chave atual (wrap forjado não importa: ela é cúmplice do servidor).
    await alice.approve(room, mallory.id);
    alice.approved.clear(); // a aprovação era de outra sessão: aqui ninguém aprovou a Mallory
    expect((await mallory.ensureRoomKey(room)).ok).toBe(true);
    await mallory.observe(carol.id);
    await mallory.safety(carol.id);
    await mallory.confirm(carol.id); // para a Mallory incluir a Carol
    expect((await mallory.rotate(room)).rotated).toBe(true);
    expect(await carol.ensureRoomKey(room)).toEqual({ ok: false });
    expect(carol.printed.join("\n")).toMatch(new RegExp(`trocada por usuário ${mallory.id}, que você não verificou`));
    // Depois de conferir e confirmar a Mallory, a Carol aceita (decisão dela).
    await carol.safety(mallory.id);
    await carol.confirm(mallory.id);
    expect((await carol.ensureRoomKey(room)).ok).toBe(true);
  });

  test("ataque: autor só APROVADO (/approve), não verificado, não basta para uma rotação ser aceita", async () => {
    const dave = await sessionFor("dave");
    await joinWith(dave, room, invite);
    await carol.approve(room, dave.id); // Carol entregou a chave ao Dave, sem verificá-lo
    expect((await dave.ensureRoomKey(room)).ok).toBe(true);
    await verify(dave, carol);
    expect((await dave.rotate(room)).rotated).toBe(true);
    expect(await carol.ensureRoomKey(room)).toEqual({ ok: false });
    await verify(carol, dave);
    expect((await carol.ensureRoomKey(room)).ok).toBe(true);
  });

  test("ataque: quem foi removido com /kick não volta a uma rotação desta sessão, mesmo se o servidor o relistar", async () => {
    const dave = await sessionFor("dave");
    await joinWith(dave, room, invite);
    await alice.approve(room, dave.id);
    await alice.kick(room, dave.id);
    await pool.query("INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)", [room, dave.id]);
    await pool.query("DELETE FROM room_bans WHERE user_id = $1", [dave.id]);
    const { rotated, left } = await alice.rotate(room);
    expect(rotated).toBe(true);
    expect(left).toContain(dave.id);
    expect((await pool.query("SELECT 1 FROM room_key_wraps WHERE room = $1 AND version = 3 AND recipient_id = $2", [room, dave.id])).rowCount).toBe(0);
  });

  test("ataque: a lista de removidos sobrevive ao reinício; um VERIFICADO removido e relistado não recebe a chave (rotação, entrega ou /approve)", async () => {
    await alice.kick(room, bob.id); // Bob é verificado pela Alice
    await pool.query("DELETE FROM room_bans WHERE user_id = $1", [bob.id]);
    await pool.query("INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)", [room, bob.id]);
    const again = new E2eeSession({ api: alice.api, me: { id: alice.id }, email: alice.email, keystorePath: alice.keystorePath, passphrase: PASS, print: () => {} });
    await again.open();
    await again.registerKeys();
    const { left } = await again.rotate(room);
    expect(left).toContain(bob.id);
    await again.distribute(room);
    await expect(again.approve(room, bob.id)).rejects.toThrow(/você removeu/);
    expect((await pool.query("SELECT 1 FROM room_key_wraps WHERE room = $1 AND version > 1 AND recipient_id = $2", [room, bob.id])).rowCount).toBe(0);
  });

  test("aprovação de quem saiu da sala deixa de valer: se o servidor o relistar, fica de fora", async () => {
    const dave = await sessionFor("dave");
    await joinWith(dave, room, invite);
    await alice.approve(room, dave.id);
    await dave.leave(room);
    await alice.rotate(room); // a rotação exigida pela saída; a aprovação do Dave cai
    await pool.query("INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)", [room, dave.id]);
    const { left } = await alice.rotate(room);
    expect(left).toContain(dave.id);
  });
});
