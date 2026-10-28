// Chave da sala (D4). O servidor guarda wraps, valida estrutura, tamanhos e
// autorização, e NUNCA vê a chave da sala. Ataques: não-membro publica ou
// lê wraps; quem não tem a chave distribui uma; destinatário errado;
// duplicata; servidor malicioso troca o remetente de um wrap.
const e2ee = require("../../shared/e2ee");
const { pool, resetDb, createUser } = require("./helpers");
const { asAgent, registerKeys, wrapFor, createKeyedRoom, join, grant, fetchRoomKey } = require("./e2ee/flow");

let alice;
let bob;
let carol;
let room;

beforeEach(async () => {
  await resetDb();
  alice = await registerKeys(asAgent(await createUser("alice")));
  bob = await registerKeys(asAgent(await createUser("bob")));
  carol = await registerKeys(asAgent(await createUser("carol")));
  room = await createKeyedRoom(alice);
});

afterAll(() => pool.end());

// Corpo de publicação com compromisso válido do signatário (para que os
// testes de autorização cheguem à checagem que pretendem testar).
const commitFor = (signer, roomId, version, roomKey) =>
  e2ee.commitRoomKey({ roomId, version, roomKey, creatorEcdsaKey: signer.identity.ecdsa.privateKey });

const wrapsOf = async (userId) =>
  (await pool.query("SELECT room, version, sender_id FROM room_key_wraps WHERE recipient_id = $1", [userId])).rows;

describe("criação da sala e versão 1", () => {
  test("rooms ganha created_by e key_version = 1; a versão 1 e o wrap do criador ficam gravados", async () => {
    const { rows } = await pool.query("SELECT created_by, key_version FROM rooms WHERE id = $1", [room.roomId]);
    expect(rows).toEqual([{ created_by: alice.id, key_version: 1 }]);
    expect((await pool.query("SELECT created_by FROM room_key_versions WHERE room = $1 AND version = 1", [room.roomId])).rows).toEqual([
      { created_by: alice.id },
    ]);
    expect(await wrapsOf(alice.id)).toEqual([{ room: room.roomId, version: 1, sender_id: alice.id }]);
  });

  test("o criador recupera a própria chave da sala", async () => {
    const key = await fetchRoomKey(alice, room.roomId);
    expect(await e2ee.primitives.exportRaw(key)).toEqual(await e2ee.primitives.exportRaw(room.roomKey));
  });

  test("ataque: publicar a versão 1 de novo (substituir a chave) → 409", async () => {
    const evilKey = await e2ee.generateRoomKey();
    const wrap = await wrapFor(alice, { roomId: room.roomId, roomKey: evilKey, recipientId: alice.id, recipientEcdhPub: alice.pub.ecdhPub });
    const c = await commitFor(alice, room.roomId, 1, evilKey);
    expect((await alice.call("post", `/rooms/${room.roomId}/keys`).send({ version: 1, wrap, ...c })).status).toBe(409);
  });

  test("ataque: membro que não é o criador não publica a versão 1 de uma sala nova", async () => {
    const created = await alice.call("post", "/createRoom").send({ name: "Sem chave ainda" });
    await join(bob, { roomId: created.body.id, inviteKey: created.body.key });
    const roomKey = await e2ee.generateRoomKey();
    const wrap = await wrapFor(bob, { roomId: created.body.id, roomKey, recipientId: bob.id, recipientEcdhPub: bob.pub.ecdhPub });
    const c = await commitFor(bob, created.body.id, 1, roomKey);
    expect((await bob.call("post", `/rooms/${created.body.id}/keys`).send({ version: 1, wrap, ...c })).status).toBe(403);
  });

  test("ataque: não-membro não publica chave de sala alheia", async () => {
    const created = await alice.call("post", "/createRoom").send({ name: "Outra" });
    const wrap = await wrapFor(carol, { roomId: created.body.id, roomKey: room.roomKey, recipientId: carol.id, recipientEcdhPub: carol.pub.ecdhPub });
    const c = await commitFor(carol, created.body.id, 1, room.roomKey);
    expect((await carol.call("post", `/rooms/${created.body.id}/keys`).send({ version: 1, wrap, ...c })).status).toBe(403);
  });

  test("versão diferente da atual (2) → 409", async () => {
    const created = await alice.call("post", "/createRoom").send({ name: "Outra" });
    const wrap = await wrapFor(alice, { roomId: created.body.id, version: 2, roomKey: room.roomKey, recipientId: alice.id, recipientEcdhPub: alice.pub.ecdhPub });
    const c = await commitFor(alice, created.body.id, 2, room.roomKey);
    expect((await alice.call("post", `/rooms/${created.body.id}/keys`).send({ version: 2, wrap, ...c })).status).toBe(409);
  });
});

describe("GET /rooms/:id/keys (os próprios wraps)", () => {
  test("ataque: não-membro não lê wraps (403)", async () => {
    const res = await carol.call("get", `/rooms/${room.roomId}/keys`);
    expect(res.status).toBe(403);
  });

  test("membro sem chave ainda recebe lista vazia; nunca recebe o wrap de outro", async () => {
    await join(bob, room);
    const res = await bob.call("get", `/rooms/${room.roomId}/keys`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ room: room.roomId, currentVersion: 1, versions: [expect.objectContaining({ version: 1, createdBy: alice.id })], wraps: [] });
  });
});

describe("pendentes e distribuição de wraps", () => {
  beforeEach(() => join(bob, room));

  test("quem tem a chave vê quem entrou sem chave, com as chaves públicas do diretório", async () => {
    const res = await alice.call("get", `/rooms/${room.roomId}/keys/pending`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      room: room.roomId,
      version: 1,
      pending: [{ userId: bob.id, name: "bob", keys: { ...bob.pub, fingerprint: await e2ee.fingerprint(bob.pub), keyEpoch: 1 } }],
    });
  });

  test("ataque: membro SEM a chave não vê pendentes (403)", async () => {
    expect((await bob.call("get", `/rooms/${room.roomId}/keys/pending`)).status).toBe(403);
  });

  test("ataque: não-membro não vê pendentes (403)", async () => {
    expect((await carol.call("get", `/rooms/${room.roomId}/keys/pending`)).status).toBe(403);
  });

  test("Alice entrega o wrap ao Bob; Bob abre e obtém a MESMA chave; Bob deixa de ser pendente", async () => {
    expect((await grant(alice, room, bob)).status).toBe(201);
    const key = await fetchRoomKey(bob, room.roomId);
    expect(await e2ee.primitives.exportRaw(key)).toEqual(await e2ee.primitives.exportRaw(room.roomKey));
    expect((await alice.call("get", `/rooms/${room.roomId}/keys/pending`)).body.pending).toEqual([]);
  });

  test("ataque: duplicata (segundo wrap para o mesmo destinatário e versão) → 409", async () => {
    await grant(alice, room, bob);
    expect((await grant(alice, room, bob)).status).toBe(409);
  });

  test("ataque: não-membro não publica wrap (403)", async () => {
    expect((await grant(carol, room, bob)).status).toBe(403);
  });

  test("ataque: membro sem a chave não publica wrap (403)", async () => {
    const dave = await registerKeys(asAgent(await createUser("dave")));
    await join(dave, room);
    expect((await grant(bob, room, dave)).status).toBe(403);
  });

  test("ataque: destinatário que não é membro → 400 e nada gravado", async () => {
    const res = await grant(alice, room, carol);
    expect(res.status).toBe(400);
    expect(await wrapsOf(carol.id)).toEqual([]);
  });

  test("versão desatualizada → 409", async () => {
    const wrap = await wrapFor(alice, { roomId: room.roomId, version: 2, roomKey: room.roomKey, recipientId: bob.id, recipientEcdhPub: bob.pub.ecdhPub });
    const res = await alice
      .call("post", `/rooms/${room.roomId}/keys/wraps`)
      .send({ version: 2, recipientId: bob.id, recipientKeyEpoch: 1, wrap });
    expect(res.status).toBe(409);
  });

  test("wrap para chave antiga do destinatário (key_epoch mudou) → 409", async () => {
    await bob.call("post", "/keys/reset").send(await e2ee.exportPublicKeys(await e2ee.generateIdentity()));
    expect((await grant(alice, room, bob)).status).toBe(409);
  });

  test.each([
    ["iv com 11 bytes", (w) => ({ ...w, iv: e2ee.encoding.toB64url(new Uint8Array(11)) })],
    ["sig com 63 bytes", (w) => ({ ...w, sig: e2ee.encoding.toB64url(new Uint8Array(63)) })],
    ["wrapped com tamanho errado", (w) => ({ ...w, wrapped: e2ee.encoding.toB64url(new Uint8Array(40)) })],
    ["ephPub que não é P-256", (w) => ({ ...w, ephPub: "AAAA" })],
    ["campo faltando", ({ sig, ...w }) => w],
  ])("estrutura inválida (%s) → 400", async (_label, tamper) => {
    const wrap = await wrapFor(alice, { roomId: room.roomId, roomKey: room.roomKey, recipientId: bob.id, recipientEcdhPub: bob.pub.ecdhPub });
    const res = await alice
      .call("post", `/rooms/${room.roomId}/keys/wraps`)
      .send({ version: 1, recipientId: bob.id, recipientKeyEpoch: 1, wrap: tamper(wrap) });
    expect(res.status).toBe(400);
  });

  test("ataque (servidor malicioso): wrap assinado pela Carol, gravado como se fosse da Alice, é rejeitado pelo cliente", async () => {
    // Carol vira membro e recebe a chave legitimamente; então "distribui" um
    // wrap com a chave que ELA escolheu, e o servidor o atribui à Alice.
    await join(carol, room);
    await grant(alice, room, carol);
    const evilKey = await e2ee.generateRoomKey();
    const evil = await wrapFor(carol, { roomId: room.roomId, roomKey: evilKey, recipientId: bob.id, recipientEcdhPub: bob.pub.ecdhPub });
    await carol.call("post", `/rooms/${room.roomId}/keys/wraps`).send({ version: 1, recipientId: bob.id, recipientKeyEpoch: 1, wrap: evil });
    await pool.query("UPDATE room_key_wraps SET sender_id = $1 WHERE recipient_id = $2", [alice.id, bob.id]);
    await expect(fetchRoomKey(bob, room.roomId)).rejects.toMatchObject({ code: "INVALID_WRAP" });
  });

  test("o servidor grava o remetente da SESSÃO (senderId no corpo é ignorado)", async () => {
    await join(carol, room);
    await grant(alice, room, carol);
    const wrap = await wrapFor(carol, { roomId: room.roomId, roomKey: room.roomKey, recipientId: bob.id, recipientEcdhPub: bob.pub.ecdhPub });
    await carol
      .call("post", `/rooms/${room.roomId}/keys/wraps`)
      .send({ version: 1, recipientId: bob.id, recipientKeyEpoch: 1, wrap, senderId: alice.id, sender_id: alice.id });
    expect(await wrapsOf(bob.id)).toEqual([{ room: room.roomId, version: 1, sender_id: carol.id }]);
  });
});

describe("POST /keys/reset apaga os wraps do próprio usuário", () => {
  test("Bob troca as chaves: perde os wraps e volta a ser pendente", async () => {
    await join(bob, room);
    await grant(alice, room, bob);
    const fresh = await e2ee.exportPublicKeys(await e2ee.generateIdentity());
    expect((await bob.call("post", "/keys/reset").send(fresh)).status).toBe(200);
    expect(await wrapsOf(bob.id)).toEqual([]);
    expect((await alice.call("get", `/rooms/${room.roomId}/keys/pending`)).body.pending.map((p) => p.userId)).toEqual([bob.id]);
    // Os wraps que Bob ENVIOU (para outros) não são afetados.
    expect(await wrapsOf(alice.id)).toHaveLength(1);
  });
});

test("nenhuma coluna de nenhuma tabela contém a chave da sala em claro (hex, base64 ou base64url)", async () => {
  await join(bob, room);
  await grant(alice, room, bob);
  const raw = Buffer.from(await e2ee.primitives.exportRaw(room.roomKey));
  const forms = [raw.toString("hex"), raw.toString("base64"), raw.toString("base64url")];
  const { rows: tables } = await pool.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public'");
  expect(tables.length).toBeGreaterThan(5);
  for (const { tablename } of tables) {
    const { rows } = await pool.query(`SELECT row_to_json(t)::text AS row FROM "${tablename}" t`);
    for (const { row } of rows) for (const form of forms) expect({ tablename, leaks: row.includes(form) }).toEqual({ tablename, leaks: false });
  }
});

describe("wrap para a chave ANTIGA do destinatário (corrida com o reset)", () => {
  // Simula o resultado da corrida: um wrap gravado com a época anterior do
  // destinatário depois que ele trocou de chave.
  const plantStaleWrap = async () => {
    await join(bob, room);
    const staleEpoch = bob.keyEpoch;
    const wrap = await wrapFor(alice, { roomId: room.roomId, roomKey: room.roomKey, recipientId: bob.id, recipientEcdhPub: bob.pub.ecdhPub });
    const fresh = await e2ee.generateIdentity();
    bob.identity = fresh;
    bob.pub = await e2ee.exportPublicKeys(fresh);
    bob.keyEpoch = (await bob.call("post", "/keys/reset").send(bob.pub)).body.keyEpoch;
    await pool.query(
      `INSERT INTO room_key_wraps (room, version, recipient_id, sender_id, recipient_key_epoch, eph_pub, iv, wrapped, sig)
       VALUES ($1, 1, $2, $3, $4, $5, $6, $7, $8)`,
      [room.roomId, bob.id, alice.id, staleEpoch, wrap.ephPub, wrap.iv, wrap.wrapped, wrap.sig]
    );
  };

  test("o wrap velho não conta: o destinatário continua pendente e não o recebe", async () => {
    await plantStaleWrap();
    expect((await alice.call("get", `/rooms/${room.roomId}/keys/pending`)).body.pending.map((p) => p.userId)).toEqual([bob.id]);
    expect((await bob.call("get", `/rooms/${room.roomId}/keys`)).body.wraps).toEqual([]);
  });

  test("um wrap novo para a chave atual SUBSTITUI o velho (sem 409) e abre", async () => {
    await plantStaleWrap();
    expect((await grant(alice, room, bob)).status).toBe(201);
    const key = await fetchRoomKey(bob, room.roomId);
    expect(await e2ee.primitives.exportRaw(key)).toEqual(await e2ee.primitives.exportRaw(room.roomKey));
  });

  test("reset e wrap concorrentes nunca deixam um wrap válido para a chave antiga", async () => {
    await join(bob, room);
    for (let i = 0; i < 5; i += 1) {
      const fresh = await e2ee.exportPublicKeys(await e2ee.generateIdentity());
      await Promise.all([grant(alice, room, bob), bob.call("post", "/keys/reset").send(fresh)]);
      const { rows } = await pool.query(
        `SELECT w.recipient_key_epoch, k.key_epoch FROM room_key_wraps w JOIN user_keys k ON k.user_id = w.recipient_id
         WHERE w.recipient_id = $1`,
        [bob.id]
      );
      for (const row of rows) expect(row.recipient_key_epoch).toBe(row.key_epoch);
      bob.pub = fresh;
      bob.keyEpoch = (await pool.query("SELECT key_epoch FROM user_keys WHERE user_id = $1", [bob.id])).rows[0].key_epoch;
      await pool.query("DELETE FROM room_key_wraps WHERE recipient_id = $1", [bob.id]);
    }
  });
});

describe("compromisso da chave: wrap com chave falsa é detectado e pode ser descartado", () => {
  beforeEach(async () => {
    await join(carol, room);
    await grant(alice, room, carol);
    await join(bob, room);
  });

  // Carol (membro com a chave) "ocupa" o wrap do Bob com uma chave que ela
  // escolheu, assinada por ela mesma: a assinatura do wrap confere.
  const squat = async () => {
    const evilKey = await e2ee.generateRoomKey();
    const evil = await wrapFor(carol, { roomId: room.roomId, roomKey: evilKey, recipientId: bob.id, recipientEcdhPub: bob.pub.ecdhPub });
    const res = await carol
      .call("post", `/rooms/${room.roomId}/keys/wraps`)
      .send({ version: 1, recipientId: bob.id, recipientKeyEpoch: bob.keyEpoch, wrap: evil });
    expect(res.status).toBe(201);
  };

  test("ataque: o cliente do Bob recusa a chave falsa (não confere com o compromisso do criador)", async () => {
    await squat();
    await expect(fetchRoomKey(bob, room.roomId)).rejects.toMatchObject({ code: "KEY_COMMITMENT_MISMATCH" });
  });

  test("Bob descarta o próprio wrap, volta a ser pendente e recebe a chave certa", async () => {
    await squat();
    expect((await bob.call("delete", `/rooms/${room.roomId}/keys/wraps/mine`)).status).toBe(204);
    expect((await alice.call("get", `/rooms/${room.roomId}/keys/pending`)).body.pending.map((p) => p.userId)).toEqual([bob.id]);
    expect((await grant(alice, room, bob)).status).toBe(201);
    const key = await fetchRoomKey(bob, room.roomId);
    expect(await e2ee.primitives.exportRaw(key)).toEqual(await e2ee.primitives.exportRaw(room.roomKey));
  });

  test("ataque (servidor malicioso): trocar o compromisso no banco faz a chave certa ser recusada (assinatura do criador)", async () => {
    await grant(alice, room, bob);
    const other = await e2ee.commitRoomKey({ roomId: room.roomId, version: 1, roomKey: await e2ee.generateRoomKey(), creatorEcdsaKey: carol.identity.ecdsa.privateKey });
    await pool.query("UPDATE room_key_versions SET commitment = $1 WHERE room = $2", [other.commitment, room.roomId]);
    await expect(fetchRoomKey(bob, room.roomId)).rejects.toMatchObject({ code: "KEY_COMMITMENT_MISMATCH" });
  });

  test("GET /rooms/:id/keys devolve o compromisso e o criador de cada versão", async () => {
    const res = await bob.call("get", `/rooms/${room.roomId}/keys`);
    expect(res.body.versions).toEqual([
      { version: 1, createdBy: alice.id, commitment: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/), commitmentSig: expect.stringMatching(/^[A-Za-z0-9_-]{86}$/) },
    ]);
  });

  test("descartar sem ter wrap → 404; não-membro → 403", async () => {
    expect((await bob.call("delete", `/rooms/${room.roomId}/keys/wraps/mine`)).status).toBe(404);
    const dave = await registerKeys(asAgent(await createUser("dave")));
    expect((await dave.call("delete", `/rooms/${room.roomId}/keys/wraps/mine`)).status).toBe(403);
  });

  test("publicar a versão sem compromisso → 400", async () => {
    const created = await alice.call("post", "/createRoom").send({ name: "Sem compromisso" });
    const wrap = await wrapFor(alice, { roomId: created.body.id, roomKey: room.roomKey, recipientId: alice.id, recipientEcdhPub: alice.pub.ecdhPub });
    expect((await alice.call("post", `/rooms/${created.body.id}/keys`).send({ version: 1, wrap })).status).toBe(400);
  });
});
