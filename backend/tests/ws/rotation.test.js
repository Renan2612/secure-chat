// Rotação da chave da sala no servidor (Etapa 4b-2, D3) e troca do convite
// (D5). Falha fechada: enquanto a rotação é exigida, nada é enviado. Ataques:
// não-membro, membro sem a chave atual, versão errada, wrap para banido ou
// não-membro, wrap ou compromisso assinado por outro, autor fora dos wraps,
// rotações concorrentes, membro que sai no meio (STALE_MEMBERSHIP), MSG_SEND
// durante a rotação exigida e kv antigo depois dela.
const e2ee = require("../../../shared/e2ee");
const { pool, resetDb } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, send, expectNoPacket } = require("./helpers");
const { asCookie, registerKeys, createKeyedRoom, join, grant, wrapFor } = require("../e2ee/flow");

let srv;
let alice; // dona
let bob; // será removido
let carol; // fica
let room;

const subscribed = async (user, roomId) => {
  const conn = await connect(srv, user.cookie);
  send(conn.ws, { type: "SUBSCRIBE", room: roomId });
  await nextPacket(conn.inbox, "SUBSCRIBED");
  return conn;
};

// Corpo de rotação de um cliente honesto: chave NOVA aleatória, compromisso
// e wraps assinados pelo autor, e o nome da sala recifrado com a chave nova
// (Etapa 5). `signer` permite forjar a assinatura.
const rotationBody = async (author, { version = 2, recipients, roomKey, signer = author, commitSigner = author }) => {
  const key = roomKey ?? (await e2ee.generateRoomKey());
  const commitment = await e2ee.commitRoomKey({ roomId: room.roomId, version, roomKey: key, creatorEcdsaKey: commitSigner.identity.ecdsa.privateKey });
  const wraps = [];
  for (const r of recipients) {
    const wrap = await wrapFor({ ...author, identity: signer.identity }, { roomId: room.roomId, version, roomKey: key, recipientId: r.id, recipientEcdhPub: r.pub.ecdhPub });
    wraps.push({ recipientId: r.id, recipientKeyEpoch: r.keyEpoch, wrap });
  }
  // Quem rotaciona recifra o MESMO nome assinado pela dona (sem re-assinar).
  const nameEnv = await e2ee.encryptRoomName({ roomKey: key, roomId: room.roomId, kv: version, payload: room.namePayload });
  return { key, body: { version, ...commitment, wraps, nameEnv } };
};

const rotate = (author, body) => author.call("post", `/rooms/${room.roomId}/keys/rotate`).send(body);
const roomRow = async () => (await pool.query("SELECT key_version, rotation_required FROM rooms WHERE id = $1", [room.roomId])).rows[0];
const versions = async () => (await pool.query("SELECT version FROM room_key_versions WHERE room = $1 ORDER BY version", [room.roomId])).rows.map((r) => r.version);

// Abre o próprio wrap da versão pedida (assinatura do remetente e
// compromisso do autor da versão, chaves do diretório).
const openVersion = async (user, version) => {
  const res = await user.call("get", `/rooms/${room.roomId}/keys`);
  const wrap = res.body.wraps.find((w) => w.version === version);
  const info = res.body.versions.find((v) => v.version === version);
  const sender = (await user.call("get", `/keys/${wrap.senderId}`)).body;
  const key = await e2ee.unwrapRoomKey({
    wrap, roomId: room.roomId, version, senderId: wrap.senderId, recipientId: user.id,
    recipientEcdhKey: user.identity.ecdh.privateKey, senderEcdsaPub: sender.ecdsaPub,
  });
  const creator = (await user.call("get", `/keys/${info.createdBy}`)).body;
  await e2ee.verifyRoomKeyCommitment({ roomKey: key, roomId: room.roomId, version, commitment: info.commitment, commitmentSig: info.commitmentSig, creatorEcdsaPub: creator.ecdsaPub });
  return e2ee.primitives.exportRaw(key);
};

const envelopeFor = async (user, roomKey, kv, cid, text = "oi") =>
  e2ee.encryptMessage({ roomKey, roomId: room.roomId, kv, senderId: user.id, cid, text, senderEcdsaKey: user.identity.ecdsa.privateKey });

beforeEach(async () => {
  await resetDb();
  srv = await startServer();
  alice = await registerKeys(asCookie(srv, await loginUser(srv, "alice")));
  bob = await registerKeys(asCookie(srv, await loginUser(srv, "bob")));
  carol = await registerKeys(asCookie(srv, await loginUser(srv, "carol")));
  room = await createKeyedRoom(alice);
  for (const u of [bob, carol]) {
    await join(u, room);
    await grant(alice, room, u);
  }
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

const removeBob = async () => {
  const res = await alice.call("delete", `/rooms/${room.roomId}/members/${bob.id}`);
  if (res.status !== 200) throw new Error(`remove: ${res.status}`);
};

describe("rotação aceita", () => {
  test("depois da remoção, a dona rotaciona: versão 2 com chave nova, rotação deixa de ser exigida, Carol abre a v2 e ainda tem a v1", async () => {
    await removeBob();
    const { key, body } = await rotationBody(alice, { recipients: [alice, carol] });
    const res = await rotate(alice, body);
    expect(res.status).toBe(201);
    expect(res.body).toEqual({ room: room.roomId, version: 2 });
    expect(await roomRow()).toEqual({ key_version: 2, rotation_required: false });
    expect(await openVersion(carol, 2)).toEqual(await e2ee.primitives.exportRaw(key));
    expect(await openVersion(carol, 1)).toEqual(await e2ee.primitives.exportRaw(room.roomKey));
    expect(await e2ee.primitives.exportRaw(key)).not.toEqual(await e2ee.primitives.exportRaw(room.roomKey));
    expect((await pool.query("SELECT created_by FROM room_key_versions WHERE room = $1 AND version = 2", [room.roomId])).rows).toEqual([{ created_by: alice.id }]);
  });

  test("qualquer membro com a chave atual rotaciona (não só a dona)", async () => {
    await removeBob();
    const { body } = await rotationBody(carol, { recipients: [alice, carol] });
    expect((await rotate(carol, body)).status).toBe(201);
  });

  test("eventos: KEY_READY a cada destinatário e KEY_ROTATED aos inscritos", async () => {
    await removeBob();
    const a = await subscribed(alice, room.roomId);
    const c = await connect(srv, carol.cookie); // sem SUBSCRIBE: recebe KEY_READY mesmo assim
    const { body } = await rotationBody(alice, { recipients: [alice, carol] });
    await rotate(alice, body);
    expect(await nextPacket(c.inbox, "ROOM_EVENT")).toEqual({ v: 1, type: "ROOM_EVENT", room: room.roomId, kind: "KEY_READY" });
    const kinds = [await nextPacket(a.inbox, "ROOM_EVENT"), await nextPacket(a.inbox, "ROOM_EVENT")].map((p) => p.kind).sort();
    expect(kinds).toEqual(["KEY_READY", "KEY_ROTATED"]);
    [a, c].forEach(({ ws }) => ws.close());
  });

  test("membro atual sem wrap na nova versão fica pendente (fluxo do /approve) e quem tem a chave recebe KEY_PENDING", async () => {
    await removeBob();
    const a = await subscribed(alice, room.roomId);
    const { body } = await rotationBody(alice, { recipients: [alice] });
    expect((await rotate(alice, body)).status).toBe(201);
    const pending = await alice.call("get", `/rooms/${room.roomId}/keys/pending`);
    expect(pending.body).toMatchObject({ version: 2, pending: [{ userId: carol.id }] });
    await new Promise((r) => setTimeout(r, 200));
    expect(a.inbox.packets.filter((p) => p.type === "ROOM_EVENT").map((p) => p.kind)).toContain("KEY_PENDING");
    a.ws.close();
  });

  test("rotação manual (sem remoção) também é aceita", async () => {
    const { body } = await rotationBody(alice, { recipients: [alice, bob, carol] });
    expect((await rotate(alice, body)).status).toBe(201);
    expect((await roomRow()).key_version).toBe(2);
  });
});

describe("ataques na rotação (nada é gravado)", () => {
  const unchanged = async () => {
    expect(await roomRow()).toEqual({ key_version: 1, rotation_required: true });
    expect(await versions()).toEqual([1]);
  };

  beforeEach(removeBob);

  test("não-membro (o próprio removido) → 403", async () => {
    const { body } = await rotationBody(bob, { recipients: [bob] });
    expect((await rotate(bob, body)).status).toBe(403);
    await unchanged();
  });

  test("sala inexistente → o mesmo 403", async () => {
    const { body } = await rotationBody(alice, { recipients: [alice, carol] });
    expect((await alice.call("post", "/rooms/999999/keys/rotate").send(body)).status).toBe(403);
  });

  test("membro sem a chave atual → 403", async () => {
    const dave = await registerKeys(asCookie(srv, await loginUser(srv, "dave")));
    const { body: inv } = await alice.call("post", `/rooms/${room.roomId}/invite/rotate`);
    await join(dave, { roomId: room.roomId, inviteKey: inv.invite });
    const { body } = await rotationBody(dave, { recipients: [alice, carol, dave] });
    expect((await rotate(dave, body)).status).toBe(403);
    await unchanged();
  });

  test.each([[1], [3]])("version %i (≠ atual + 1) → 409", async (version) => {
    const { body } = await rotationBody(alice, { version, recipients: [alice, carol] });
    expect((await rotate(alice, body)).status).toBe(409);
    await unchanged();
  });

  test("wrap para o banido → 409 STALE_MEMBERSHIP com a lista atual", async () => {
    const { body } = await rotationBody(alice, { recipients: [alice, carol, bob] });
    const res = await rotate(alice, body);
    expect(res.status).toBe(409);
    expect(res.body).toEqual({
      code: "STALE_MEMBERSHIP",
      message: expect.any(String),
      members: [
        { userId: alice.id, keyEpoch: 1 },
        { userId: carol.id, keyEpoch: 1 },
      ],
    });
    await unchanged();
    expect((await pool.query("SELECT 1 FROM room_key_wraps WHERE recipient_id = $1", [bob.id])).rowCount).toBe(0);
  });

  test("wrap para quem nunca foi membro → 409 STALE_MEMBERSHIP", async () => {
    const dave = await registerKeys(asCookie(srv, await loginUser(srv, "dave")));
    const { body } = await rotationBody(alice, { recipients: [alice, carol, dave] });
    expect((await rotate(alice, body)).body.code).toBe("STALE_MEMBERSHIP");
    await unchanged();
  });

  test("wrap assinado por outro (Carol assina, Alice envia) → 400", async () => {
    const { body } = await rotationBody(alice, { recipients: [alice, carol], signer: carol });
    expect((await rotate(alice, body)).status).toBe(400);
    await unchanged();
  });

  test("compromisso assinado por outro → 400", async () => {
    const { body } = await rotationBody(alice, { recipients: [alice, carol], commitSigner: carol });
    expect((await rotate(alice, body)).status).toBe(400);
    await unchanged();
  });

  test("um único wrap adulterado (assinatura de outro contexto) → 400", async () => {
    const { body } = await rotationBody(alice, { recipients: [alice, carol] });
    body.wraps[1].wrap = body.wraps[0].wrap; // wrap da Alice apresentado como da Carol
    expect((await rotate(alice, body)).status).toBe(400);
    await unchanged();
  });

  test("autor fora dos wraps → 400", async () => {
    const { body } = await rotationBody(alice, { recipients: [carol] });
    expect((await rotate(alice, body)).status).toBe(400);
    await unchanged();
  });

  test("destinatário repetido → 400", async () => {
    const { body } = await rotationBody(alice, { recipients: [alice, carol, carol] });
    expect((await rotate(alice, body)).status).toBe(400);
    await unchanged();
  });

  test("key_epoch desatualizado de um destinatário → 409 STALE_MEMBERSHIP", async () => {
    await carol.call("post", "/keys/reset").send(await e2ee.exportPublicKeys(await e2ee.generateIdentity()));
    const { body } = await rotationBody(alice, { recipients: [alice, carol] });
    const res = await rotate(alice, body);
    expect(res.status).toBe(409);
    expect(res.body.members).toContainEqual({ userId: carol.id, keyEpoch: 2 });
    await unchanged();
  });

  test("rotações concorrentes: uma vence (201), a outra recebe 409", async () => {
    const first = await rotationBody(alice, { recipients: [alice, carol] });
    const second = await rotationBody(carol, { recipients: [alice, carol] });
    const statuses = (await Promise.all([rotate(alice, first.body), rotate(carol, second.body)])).map((r) => r.status).sort();
    expect(statuses).toEqual([201, 409]);
    expect(await versions()).toEqual([1, 2]);
    expect((await pool.query("SELECT COUNT(*)::int AS n FROM room_key_wraps WHERE room = $1 AND version = 2", [room.roomId])).rows[0].n).toBe(2);
  });

  test("STALE_MEMBERSHIP: Carol sai entre a montagem e o envio; o cliente refaz com a lista nova", async () => {
    const { body } = await rotationBody(alice, { recipients: [alice, carol] });
    await carol.call("post", `/rooms/${room.roomId}/leave`);
    const res = await rotate(alice, body);
    expect(res.status).toBe(409);
    expect(res.body).toMatchObject({ code: "STALE_MEMBERSHIP", members: [{ userId: alice.id, keyEpoch: 1 }] });
    await unchanged();
    const redo = await rotationBody(alice, { recipients: [alice] });
    expect((await rotate(alice, redo.body)).status).toBe(201);
  });
});

describe("MSG_SEND e a rotação", () => {
  test("ataque: durante rotation_required, MSG_SEND → ERROR ROTATION_PENDING e nada é gravado", async () => {
    await removeBob();
    const c = await subscribed(carol, room.roomId);
    send(c.ws, { type: "MSG_SEND", id: "r", room: room.roomId, cid: "x", body: await envelopeFor(carol, room.roomKey, 1, "x") });
    expect(await nextPacket(c.inbox, "ERROR")).toMatchObject({ code: "ROTATION_PENDING", ref: "r" });
    expect((await pool.query("SELECT 1 FROM messages WHERE room = $1", [room.roomId])).rowCount).toBe(0);
    await expectNoPacket(c.inbox, "MSG_DELIVER");
    c.ws.close();
  });

  test("ataque: kv antigo é recusado depois da rotação (KEY_VERSION_MISMATCH); o kv novo passa", async () => {
    await removeBob();
    const { key, body } = await rotationBody(alice, { recipients: [alice, carol] });
    await rotate(alice, body);
    const c = await subscribed(carol, room.roomId);
    send(c.ws, { type: "MSG_SEND", id: "old", room: room.roomId, cid: "old", body: await envelopeFor(carol, room.roomKey, 1, "old") });
    expect(await nextPacket(c.inbox, "ERROR")).toMatchObject({ code: "KEY_VERSION_MISMATCH", ref: "old" });
    send(c.ws, { type: "MSG_SEND", id: "new", room: room.roomId, cid: "new", body: await envelopeFor(carol, key, 2, "new") });
    expect(await nextPacket(c.inbox, "MSG_ACK")).toMatchObject({ cid: "new" });
    c.ws.close();
  });

  test("não-membro continua recebendo NOT_MEMBER (não ROTATION_PENDING: não revela o estado da sala)", async () => {
    await removeBob();
    const b = await connect(srv, bob.cookie);
    send(b.ws, { type: "MSG_SEND", id: "b", room: room.roomId, cid: "b", body: await envelopeFor(bob, room.roomKey, 1, "b") });
    expect(await nextPacket(b.inbox, "ERROR")).toMatchObject({ code: "NOT_MEMBER" });
    b.ws.close();
  });
});

describe("troca do convite (POST /rooms/:id/invite/rotate)", () => {
  test("a dona recebe um convite novo uma única vez; o antigo deixa de valer", async () => {
    const res = await alice.call("post", `/rooms/${room.roomId}/invite/rotate`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ room: room.roomId, invite: expect.stringMatching(/^[0-9a-f]{32}$/) });
    const dave = asCookie(srv, await loginUser(srv, "dave"));
    expect((await dave.call("post", "/joinRooms").send({ idRoom: room.roomId, key: room.inviteKey })).status).toBe(403);
    expect((await dave.call("post", "/joinRooms").send({ idRoom: room.roomId, key: res.body.invite })).status).toBe(200);
  });

  test("ataque: membro que não é dono → 403; não-membro → 404", async () => {
    expect((await carol.call("post", `/rooms/${room.roomId}/invite/rotate`)).status).toBe(403);
    const dave = asCookie(srv, await loginUser(srv, "dave"));
    expect((await dave.call("post", `/rooms/${room.roomId}/invite/rotate`)).status).toBe(404);
  });
});

describe("sala sem nenhum membro com a chave atual (acréscimo a)", () => {
  test("ninguém rotaciona, o envio fica bloqueado, e a saída é o último membro sair (sala apagada)", async () => {
    await carol.call("post", `/rooms/${room.roomId}/leave`); // exige rotação
    await alice.call("post", `/rooms/${room.roomId}/owner`).send({ userId: bob.id });
    await alice.call("post", `/rooms/${room.roomId}/leave`);
    // O único que resta trocou de chave (outro dispositivo): perdeu os wraps.
    await bob.call("post", "/keys/reset").send(await e2ee.exportPublicKeys((bob.identity = await e2ee.generateIdentity())));
    const fresh = await bob.call("get", `/keys/${bob.id}`);
    bob.pub = { ecdhPub: fresh.body.ecdhPub, ecdsaPub: fresh.body.ecdsaPub };
    bob.keyEpoch = fresh.body.keyEpoch;
    const { body } = await rotationBody(bob, { recipients: [bob] });
    expect((await rotate(bob, body)).status).toBe(403);
    const b = await subscribed(bob, room.roomId);
    send(b.ws, { type: "MSG_SEND", id: "x", room: room.roomId, cid: "x", body: await envelopeFor(bob, room.roomKey, 1, "x") });
    expect(await nextPacket(b.inbox, "ERROR")).toMatchObject({ code: "ROTATION_PENDING" });
    expect((await bob.call("post", `/rooms/${room.roomId}/leave`)).body).toEqual({ room: room.roomId, roomDeleted: true });
    expect((await pool.query("SELECT 1 FROM rooms WHERE id = $1", [room.roomId])).rowCount).toBe(0);
    b.ws.close();
  });
});

describe("limites do corpo da rotação (acréscimo c)", () => {
  test("mais de 200 wraps → 400, nada gravado", async () => {
    const { body } = await rotationBody(alice, { recipients: [alice] });
    body.wraps = Array.from({ length: 201 }, (_, n) => ({ ...body.wraps[0], recipientId: n + 1 }));
    expect((await rotate(alice, body)).status).toBe(400);
    expect(await versions()).toEqual([1]);
  });

  test("corpo acima de 100 KB → 413, nada gravado", async () => {
    const { body } = await rotationBody(alice, { recipients: [alice] });
    body.padding = "x".repeat(101 * 1024);
    expect((await rotate(alice, body)).status).toBe(413);
    expect(await versions()).toEqual([1]);
  });

  test("as outras rotas continuam com o limite de 10 KB", async () => {
    const res = await alice.call("post", `/rooms/${room.roomId}/owner`).send({ userId: bob.id, padding: "x".repeat(11 * 1024) });
    expect(res.status).toBe(413);
  });
});

describe("achados da revisão de testes", () => {
  test("ataque: entregar a chave ANTIGA a quem entra durante a rotação exigida → 409 ROTATION_PENDING, nenhum wrap", async () => {
    await carol.call("post", `/rooms/${room.roomId}/leave`);
    const dave = await registerKeys(asCookie(srv, await loginUser(srv, "dave")));
    await join(dave, room);
    const res = await grant(alice, room, dave);
    expect(res.status).toBe(409);
    expect(res.body).toMatchObject({ code: "ROTATION_PENDING" });
    expect((await pool.query("SELECT 1 FROM room_key_wraps WHERE recipient_id = $1", [dave.id])).rowCount).toBe(0);
  });

  test("ataque: quem saiu e voltou (sair não bane) não recebe a chave antiga enquanto a rotação é exigida", async () => {
    await carol.call("post", `/rooms/${room.roomId}/leave`);
    await join(carol, room);
    expect((await grant(alice, room, carol)).status).toBe(409);
    expect((await carol.call("get", `/rooms/${room.roomId}/keys`)).body).toMatchObject({ wraps: [], rotationRequired: true });
  });

  test.each([
    ["wraps assinados para a v1", { wrapVersion: 1 }],
    ["wraps assinados para outra sala", { wrapRoom: 999 }],
  ])("ataque: rotação v2 com %s → 400, nada gravado", async (_label, { wrapVersion = 2, wrapRoom }) => {
    await removeBob();
    const key = await e2ee.generateRoomKey();
    const commitment = await e2ee.commitRoomKey({ roomId: room.roomId, version: 2, roomKey: key, creatorEcdsaKey: alice.identity.ecdsa.privateKey });
    const wraps = [];
    for (const r of [alice, carol]) {
      const wrap = await wrapFor(alice, { roomId: wrapRoom ?? room.roomId, version: wrapVersion, roomKey: key, recipientId: r.id, recipientEcdhPub: r.pub.ecdhPub });
      wraps.push({ recipientId: r.id, recipientKeyEpoch: 1, wrap });
    }
    expect((await rotate(alice, { version: 2, ...commitment, wraps })).status).toBe(400);
    expect(await versions()).toEqual([1]);
  });
});
