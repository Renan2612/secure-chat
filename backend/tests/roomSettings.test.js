// Etapa 5: ajustes que só o dono faz (retenção A1, nome cifrado A3,
// banimentos A2) e o nome da sala que nunca vai em claro ao servidor.
// Ataques: não-dono e não-membro mexendo em retenção, nome ou banimentos;
// nome cifrado com a versão errada; publicar/rotacionar sem o nome; nome
// em claro em qualquer coluna do banco.
const e2ee = require("../../shared/e2ee");
const { pool, resetDb, createUser, fakeNameEnv } = require("./helpers");
const { asAgent, registerKeys, createKeyedRoom, join, grant, wrapFor, sealName } = require("./e2ee/flow");

let alice; // dona
let bob; // membro com a chave
let carol; // não-membro
let room;

beforeEach(async () => {
  await resetDb();
  alice = await registerKeys(asAgent(await createUser("alice")));
  bob = await registerKeys(asAgent(await createUser("bob")));
  carol = await registerKeys(asAgent(await createUser("carol")));
  room = await createKeyedRoom(alice, "Sala do grupo");
  await join(bob, room);
  await grant(alice, room, bob);
});
afterAll(() => pool.end());

const roomRow = async () => (await pool.query("SELECT * FROM rooms WHERE id = $1", [room.roomId])).rows[0];

describe("retenção (PUT /rooms/:id/retention)", () => {
  test("a dona define e remove; GET /rooms mostra", async () => {
    const res = await alice.agent.put(`/rooms/${room.roomId}/retention`).send({ retentionSeconds: 3600 });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ room: room.roomId, retentionSeconds: 3600 });
    expect((await bob.agent.get("/rooms")).body[0]).toMatchObject({ id: room.roomId, retentionSeconds: 3600 });
    expect((await alice.agent.put(`/rooms/${room.roomId}/retention`).send({ retentionSeconds: null })).status).toBe(200);
    expect((await roomRow()).retention_seconds).toBeNull();
  });

  test("ATAQUE: membro que não é o dono → 403 e nada muda", async () => {
    expect((await bob.agent.put(`/rooms/${room.roomId}/retention`).send({ retentionSeconds: 60 })).status).toBe(403);
    expect((await roomRow()).retention_seconds).toBeNull();
  });

  test("ATAQUE: não-membro e sala inexistente → o mesmo 404", async () => {
    const a = await carol.agent.put(`/rooms/${room.roomId}/retention`).send({ retentionSeconds: 60 });
    const b = await carol.agent.put("/rooms/999999/retention").send({ retentionSeconds: 60 });
    expect([a.status, b.status]).toEqual([404, 404]);
    expect(a.body).toEqual(b.body);
  });

  test.each([
    ["abaixo de 1 min", 59],
    ["acima de 7 dias", 604801],
    ["fracionário", 60.5],
    ["texto", "3600"],
    ["ausente", undefined],
  ])("valor inválido (%s) → 400", async (_label, retentionSeconds) => {
    const res = await alice.agent.put(`/rooms/${room.roomId}/retention`).send({ retentionSeconds });
    expect(res.status).toBe(400);
  });
});

describe("nome cifrado (A3)", () => {
  test("ATAQUE: o nome em claro não aparece em NENHUMA coluna de nenhuma tabela (criar, rotacionar, renomear)", async () => {
    const marker = `NOME-SECRETO-${Date.now()}`;
    const r = await createKeyedRoom(alice, marker);
    // Rotação manual com o nome recifrado, e uma troca de nome.
    const roomKey = await e2ee.generateRoomKey();
    const commitment = await e2ee.commitRoomKey({ roomId: r.roomId, version: 2, roomKey, creatorEcdsaKey: alice.identity.ecdsa.privateKey });
    const wrap = await wrapFor(alice, { roomId: r.roomId, version: 2, roomKey, recipientId: alice.id, recipientEcdhPub: alice.pub.ecdhPub });
    const { nameEnv } = await sealName(alice, { roomKey, roomId: r.roomId, kv: 2, name: `${marker}-v2`, seq: 2 });
    const rotated = await alice.agent
      .post(`/rooms/${r.roomId}/keys/rotate`)
      .send({ version: 2, ...commitment, wraps: [{ recipientId: alice.id, recipientKeyEpoch: alice.keyEpoch, wrap }], nameEnv });
    expect(rotated.status).toBe(201);
    const { nameEnv: renamed } = await sealName(alice, { roomKey, roomId: r.roomId, kv: 2, name: `${marker}-novo`, seq: 3 });
    expect((await alice.agent.put(`/rooms/${r.roomId}/name`).send({ nameEnv: renamed })).status).toBe(200);

    const { rows: tables } = await pool.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public'");
    let dump = "";
    for (const { tablename } of tables) {
      const { rows } = await pool.query(`SELECT row_to_json(t)::text AS j FROM "${tablename}" t`);
      dump += rows.map((x) => x.j).join("\n");
    }
    expect(dump).toContain(JSON.parse(renamed).ct); // controle positivo: a linha da sala foi varrida
    expect(dump).not.toContain("NOME-SECRETO");
    expect(dump).not.toContain(Buffer.from(marker).toString("base64url").slice(0, 16));
    // E quem tem a chave lê o nome atual.
    const listed = (await alice.agent.get("/rooms")).body.find((x) => x.id === r.roomId);
    expect(listed).not.toHaveProperty("name");
    expect((await e2ee.decryptRoomName({ roomId: r.roomId, nameEnv: listed.nameEnv, roomKeys: { 2: roomKey } })).name).toBe(`${marker}-novo`);
  });

  test("GET /rooms devolve id e nameEnv (o membro decifra com a chave da sala)", async () => {
    const [listed] = (await bob.agent.get("/rooms")).body;
    expect(Object.keys(listed).sort()).toEqual(["id", "nameEnv", "nummessages", "ownerId", "retentionSeconds"]);
    expect((await e2ee.decryptRoomName({ roomId: room.roomId, nameEnv: listed.nameEnv, roomKeys: { 1: room.roomKey } })).name).toBe("Sala do grupo");
  });

  test("publicar a v1 SEM o nome → 400 (obrigatório); com o nome de outra versão → 400", async () => {
    const created = await alice.agent.post("/createRoom").send({});
    const roomId = created.body.id;
    const roomKey = await e2ee.generateRoomKey();
    const wrap = await wrapFor(alice, { roomId, roomKey, recipientId: alice.id, recipientEcdhPub: alice.pub.ecdhPub });
    const c = await e2ee.commitRoomKey({ roomId, version: 1, roomKey, creatorEcdsaKey: alice.identity.ecdsa.privateKey });
    expect((await alice.agent.post(`/rooms/${roomId}/keys`).send({ version: 1, wrap, ...c })).status).toBe(400);
    expect((await alice.agent.post(`/rooms/${roomId}/keys`).send({ version: 1, wrap, ...c, nameEnv: fakeNameEnv(2) })).status).toBe(400);
    expect((await alice.agent.post(`/rooms/${roomId}/keys`).send({ version: 1, wrap, ...c, nameEnv: "Sala em claro" })).status).toBe(400);
    expect((await pool.query("SELECT 1 FROM room_key_versions WHERE room = $1", [roomId])).rowCount).toBe(0);
  });

  test("rotação SEM o nome recifrado → 400 e nada muda", async () => {
    const roomKey = await e2ee.generateRoomKey();
    const commitment = await e2ee.commitRoomKey({ roomId: room.roomId, version: 2, roomKey, creatorEcdsaKey: alice.identity.ecdsa.privateKey });
    const wraps = [];
    for (const u of [alice, bob]) {
      const wrap = await wrapFor(alice, { roomId: room.roomId, version: 2, roomKey, recipientId: u.id, recipientEcdhPub: u.pub.ecdhPub });
      wraps.push({ recipientId: u.id, recipientKeyEpoch: u.keyEpoch, wrap });
    }
    const url = `/rooms/${room.roomId}/keys/rotate`;
    expect((await alice.agent.post(url).send({ version: 2, ...commitment, wraps })).status).toBe(400);
    // Nome cifrado ainda com a chave ANTIGA (kv 1): quem saiu o leria.
    expect((await alice.agent.post(url).send({ version: 2, ...commitment, wraps, nameEnv: fakeNameEnv(1) })).status).toBe(400);
    expect((await roomRow()).key_version).toBe(1);
  });

  test("rotação com nameEnv: null EXPLÍCITO (quem rotaciona não tem nome assinado válido) → 201 e o nome fica vazio", async () => {
    const roomKey = await e2ee.generateRoomKey();
    const commitment = await e2ee.commitRoomKey({ roomId: room.roomId, version: 2, roomKey, creatorEcdsaKey: bob.identity.ecdsa.privateKey });
    const wraps = [];
    for (const u of [alice, bob]) {
      const wrap = await wrapFor(bob, { roomId: room.roomId, version: 2, roomKey, recipientId: u.id, recipientEcdhPub: u.pub.ecdhPub });
      wraps.push({ recipientId: u.id, recipientKeyEpoch: u.keyEpoch, wrap });
    }
    const res = await bob.agent.post(`/rooms/${room.roomId}/keys/rotate`).send({ version: 2, ...commitment, wraps, nameEnv: null });
    expect(res.status).toBe(201);
    expect(await roomRow()).toMatchObject({ key_version: 2, name_env: null });
  });

  test("PUT /rooms/:id/name: a dona troca com a chave atual", async () => {
    const { nameEnv } = await sealName(alice, { roomKey: room.roomKey, roomId: room.roomId, name: "Novo nome", seq: 2 });
    expect((await alice.agent.put(`/rooms/${room.roomId}/name`).send({ nameEnv })).status).toBe(200);
    expect((await roomRow()).name_env).toBe(nameEnv);
  });

  test("ATAQUE: membro que não é o dono troca o nome → 403; não-membro → 404", async () => {
    const before = (await roomRow()).name_env;
    const { nameEnv } = await sealName(alice, { roomKey: room.roomKey, roomId: room.roomId, name: "Sequestrada", seq: 2 });
    expect((await bob.agent.put(`/rooms/${room.roomId}/name`).send({ nameEnv })).status).toBe(403);
    expect((await carol.agent.put(`/rooms/${room.roomId}/name`).send({ nameEnv })).status).toBe(404);
    expect((await roomRow()).name_env).toBe(before);
  });

  test("nome cifrado com versão que não é a atual → 409; malformado ou em claro → 400", async () => {
    expect((await alice.agent.put(`/rooms/${room.roomId}/name`).send({ nameEnv: fakeNameEnv(2) })).status).toBe(409);
    expect((await alice.agent.put(`/rooms/${room.roomId}/name`).send({ nameEnv: "Nome em claro" })).status).toBe(400);
    expect((await alice.agent.put(`/rooms/${room.roomId}/name`).send({ name: "Nome em claro" })).status).toBe(400);
  });

  test("com a rotação pendente (alguém saiu) → 409: o nome novo só vai recifrado com a chave nova", async () => {
    expect((await bob.agent.post(`/rooms/${room.roomId}/leave`)).status).toBe(200);
    const { nameEnv } = await sealName(alice, { roomKey: room.roomKey, roomId: room.roomId, name: "x", seq: 2 });
    const res = await alice.agent.put(`/rooms/${room.roomId}/name`).send({ nameEnv });
    expect(res.status).toBe(409);
    expect(res.body.code).toBe("ROTATION_PENDING");
  });

  test("o banco recusa nome em claro mesmo fora da API (CHECK)", async () => {
    await expect(pool.query("UPDATE rooms SET name_env = 'Sala em claro' WHERE id = $1", [room.roomId])).rejects.toThrow(/check/i);
  });
});

describe("banimentos (GET /rooms/:id/bans, DELETE /rooms/:id/bans/:userId)", () => {
  beforeEach(async () => {
    const removed = await alice.agent.delete(`/rooms/${room.roomId}/members/${bob.id}`);
    expect(removed.status).toBe(200);
    room.inviteKey = removed.body.invite;
  });

  test("a dona lista e desbane; o desbanido precisa de convite válido para voltar", async () => {
    const listed = await alice.agent.get(`/rooms/${room.roomId}/bans`);
    expect(listed.status).toBe(200);
    expect(listed.body).toEqual({ room: room.roomId, bans: [{ userId: bob.id, name: "bob" }] });
    expect((await bob.agent.post("/joinRooms").send({ idRoom: room.roomId, key: room.inviteKey })).status).toBe(403);
    expect((await alice.agent.delete(`/rooms/${room.roomId}/bans/${bob.id}`)).status).toBe(204);
    expect((await alice.agent.get(`/rooms/${room.roomId}/bans`)).body.bans).toEqual([]);
    // Desbanir não devolve o vínculo nem a chave.
    expect((await pool.query("SELECT 1 FROM rooms_users WHERE room = $1 AND user_id = $2", [room.roomId, bob.id])).rowCount).toBe(0);
    expect((await bob.agent.post("/joinRooms").send({ idRoom: room.roomId, key: room.inviteKey })).status).toBe(200);
  });

  test("ATAQUE: membro que não é o dono não lista nem desbane (403)", async () => {
    await join(carol, room);
    expect((await carol.agent.get(`/rooms/${room.roomId}/bans`)).status).toBe(403);
    expect((await carol.agent.delete(`/rooms/${room.roomId}/bans/${bob.id}`)).status).toBe(403);
    expect((await pool.query("SELECT 1 FROM room_bans WHERE room = $1", [room.roomId])).rowCount).toBe(1);
  });

  test("ATAQUE: o próprio banido e a sala inexistente recebem o mesmo 404", async () => {
    const own = await bob.agent.delete(`/rooms/${room.roomId}/bans/${bob.id}`);
    const none = await bob.agent.get("/rooms/999999/bans");
    expect([own.status, none.status]).toEqual([404, 404]);
    expect((await pool.query("SELECT 1 FROM room_bans WHERE room = $1", [room.roomId])).rowCount).toBe(1);
  });

  test("desbanir quem não está banido → 404 genérico", async () => {
    const res = await alice.agent.delete(`/rooms/${room.roomId}/bans/${carol.id}`);
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ message: "Sala ou membro inexistente" });
  });
});
