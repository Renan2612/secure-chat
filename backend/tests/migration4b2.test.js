// Migração da Etapa 4b-2 (ciclo de vida dos membros): rooms ganha owner_id,
// rotation_required e invite_hash (o convite deixa de ficar em claro);
// room_bans guarda quem foi removido; apagar a sala leva junto mensagens,
// versões, wraps, vínculos e banimentos.
const crypto = require("node:crypto");
const { pool, resetDb, createUser, insertMessage } = require("./helpers");
const { asAgent, registerKeys, createKeyedRoom, join, grant } = require("./e2ee/flow");

let alice;
let bob;

beforeEach(async () => {
  await resetDb();
  alice = await registerKeys(asAgent(await createUser("alice")));
  bob = await registerKeys(asAgent(await createUser("bob")));
});

afterAll(() => pool.end());

const columnsOf = async (table) =>
  (await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name = $1", [table])).rows.map((r) => r.column_name);

test("createRoom grava owner_id = criador e rotation_required = false", async () => {
  const room = await createKeyedRoom(alice);
  const { rows } = await pool.query("SELECT owner_id, created_by, rotation_required FROM rooms WHERE id = $1", [room.roomId]);
  expect(rows).toEqual([{ owner_id: alice.id, created_by: alice.id, rotation_required: false }]);
});

test("ataque (quem lê o banco): o convite não fica em claro, só o SHA-256 dele", async () => {
  const room = await createKeyedRoom(alice);
  expect(await columnsOf("rooms")).not.toContain("key");
  const { rows } = await pool.query("SELECT row_to_json(rooms)::text AS row, invite_hash FROM rooms WHERE id = $1", [room.roomId]);
  expect(rows[0].row).not.toContain(room.inviteKey);
  expect(rows[0].invite_hash).toBe(crypto.createHash("sha256").update(room.inviteKey, "utf8").digest("hex"));
});

test("o convite continua funcionando (comparação dos hashes)", async () => {
  const room = await createKeyedRoom(alice);
  expect((await bob.call("post", "/joinRooms").send({ idRoom: room.roomId, key: room.inviteKey })).status).toBe(200);
});

test("o banco recusa invite_hash fora do formato (hex de 64)", async () => {
  const room = await createKeyedRoom(alice);
  await expect(pool.query("UPDATE rooms SET invite_hash = 'convite-em-claro' WHERE id = $1", [room.roomId])).rejects.toMatchObject({ code: "23514" });
});

test("room_bans: um banimento por (sala, usuário)", async () => {
  const room = await createKeyedRoom(alice);
  await pool.query("INSERT INTO room_bans (room, user_id) VALUES ($1, $2)", [room.roomId, bob.id]);
  await expect(pool.query("INSERT INTO room_bans (room, user_id) VALUES ($1, $2)", [room.roomId, bob.id])).rejects.toMatchObject({ code: "23505" });
});

test("o dono tem de existir (FK) e rotation_required não aceita NULL", async () => {
  const room = await createKeyedRoom(alice);
  await expect(pool.query("UPDATE rooms SET owner_id = 999999 WHERE id = $1", [room.roomId])).rejects.toMatchObject({ code: "23503" });
  await expect(pool.query("UPDATE rooms SET rotation_required = NULL WHERE id = $1", [room.roomId])).rejects.toMatchObject({ code: "23502" });
});

test("apagar a sala apaga em cascata mensagens, versões, wraps, vínculos e banimentos", async () => {
  const room = await createKeyedRoom(alice);
  await join(bob, room);
  await grant(alice, room, bob);
  await insertMessage(room.roomId, alice.id, "m1");
  const carol = await createUser("carol");
  await pool.query("INSERT INTO room_bans (room, user_id) VALUES ($1, $2)", [room.roomId, carol.id]);
  await pool.query("DELETE FROM rooms WHERE id = $1", [room.roomId]);
  for (const table of ["messages", "room_key_versions", "room_key_wraps", "rooms_users", "room_bans"]) {
    expect((await pool.query(`SELECT COUNT(*)::int AS n FROM ${table} WHERE room = $1`, [room.roomId])).rows[0].n).toBe(0);
  }
});
