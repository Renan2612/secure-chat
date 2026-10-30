// Ciclo de vida dos membros (Etapa 4b-2, D1 e D2): sair, transferir o cargo
// de dono e remover. Ataques: não-dono remove; dono remove a si ou outro
// dono; o removido tenta continuar (SUBSCRIBE, histórico, wraps, convite
// antigo, MSG_DELIVER); remoção concorrente com envio de mensagem.
const { pool, resetDb, fakeEnvelope } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, send, expectNoPacket } = require("./helpers");
const { asCookie, registerKeys, createKeyedRoom, join, grant } = require("../e2ee/flow");

let srv;
let alice; // dona
let bob;
let carol;
let room;

const subscribed = async (user, roomId) => {
  const conn = await connect(srv, user.cookie);
  send(conn.ws, { type: "SUBSCRIBE", room: roomId });
  await nextPacket(conn.inbox, "SUBSCRIBED");
  return conn;
};

const remove = (by, target) => by.call("delete", `/rooms/${room.roomId}/members/${target.id}`);
const leave = (user) => user.call("post", `/rooms/${room.roomId}/leave`);
const transfer = (by, target) => by.call("post", `/rooms/${room.roomId}/owner`).send({ userId: target.id });
const roomRow = async () => (await pool.query("SELECT owner_id, rotation_required, invite_hash FROM rooms WHERE id = $1", [room.roomId])).rows[0];
const memberIds = async () =>
  (await pool.query("SELECT user_id FROM rooms_users WHERE room = $1 ORDER BY user_id", [room.roomId])).rows.map((r) => r.user_id);
const wrapsOf = async (userId) =>
  (await pool.query("SELECT version FROM room_key_wraps WHERE room = $1 AND recipient_id = $2", [room.roomId, userId])).rowCount;

beforeEach(async () => {
  await resetDb();
  srv = await startServer();
  alice = await registerKeys(asCookie(srv, await loginUser(srv, "alice")));
  bob = await registerKeys(asCookie(srv, await loginUser(srv, "bob")));
  carol = await registerKeys(asCookie(srv, await loginUser(srv, "carol")));
  room = await createKeyedRoom(alice);
  await join(bob, room);
  await grant(alice, room, bob);
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

describe("remover (DELETE /rooms/:id/members/:userId)", () => {
  test("a dona remove o Bob: sai de rooms_users, perde TODOS os wraps, é banido, exige rotação e gera convite novo", async () => {
    const before = await roomRow();
    const res = await remove(alice, bob);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ room: room.roomId, userId: bob.id, invite: expect.stringMatching(/^[0-9a-f]{32}$/) });
    expect(await memberIds()).toEqual([alice.id]);
    expect(await wrapsOf(bob.id)).toBe(0);
    expect(await wrapsOf(alice.id)).toBe(1);
    expect((await pool.query("SELECT 1 FROM room_bans WHERE room = $1 AND user_id = $2", [room.roomId, bob.id])).rowCount).toBe(1);
    const after = await roomRow();
    expect(after.rotation_required).toBe(true);
    expect(after.invite_hash).not.toBe(before.invite_hash);
  });

  test("as mensagens antigas do removido permanecem", async () => {
    const b = await subscribed(bob, room.roomId);
    send(b.ws, { type: "MSG_SEND", room: room.roomId, cid: "antes", body: fakeEnvelope() });
    await nextPacket(b.inbox, "MSG_ACK");
    await remove(alice, bob);
    expect((await pool.query("SELECT 1 FROM messages WHERE user_id = $1", [bob.id])).rowCount).toBe(1);
    b.ws.close();
  });

  test("o removido é desinscrito (sem fechar a conexão) e recebe ROOM_EVENT REMOVED; os inscritos recebem ROTATION_PENDING", async () => {
    const b = await subscribed(bob, room.roomId);
    const a = await subscribed(alice, room.roomId);
    await remove(alice, bob);
    expect(await nextPacket(b.inbox, "ROOM_EVENT")).toEqual({ v: 1, type: "ROOM_EVENT", room: room.roomId, kind: "REMOVED" });
    expect(await nextPacket(a.inbox, "ROOM_EVENT")).toEqual({ v: 1, type: "ROOM_EVENT", room: room.roomId, kind: "ROTATION_PENDING" });
    expect(srv.realtime.registry.subscribers(room.roomId).map((c) => c.userId)).toEqual([alice.id]);
    expect(b.inbox.closed).toBeNull();
    send(b.ws, { type: "PING", id: "p" });
    await nextPacket(b.inbox, "PONG");
    [a, b].forEach(({ ws }) => ws.close());
  });

  test("ataque: o removido não recebe MSG_DELIVER depois", async () => {
    const b = await subscribed(bob, room.roomId);
    await remove(alice, bob);
    await nextPacket(b.inbox, "ROOM_EVENT");
    await pool.query("UPDATE rooms SET rotation_required = FALSE WHERE id = $1", [room.roomId]); // isola o teste da rotação
    const a = await subscribed(alice, room.roomId);
    send(a.ws, { type: "MSG_SEND", room: room.roomId, cid: "depois", body: fakeEnvelope() });
    await nextPacket(a.inbox, "MSG_DELIVER");
    await expectNoPacket(b.inbox, "MSG_DELIVER");
    [a, b].forEach(({ ws }) => ws.close());
  });

  test("ataque: o removido não faz SUBSCRIBE, não lê histórico nem wraps", async () => {
    await remove(alice, bob);
    const b = await connect(srv, bob.cookie);
    send(b.ws, { type: "SUBSCRIBE", id: "s", room: room.roomId });
    expect(await nextPacket(b.inbox, "ERROR")).toMatchObject({ code: "NOT_MEMBER" });
    expect((await bob.call("get", `/messages/${room.roomId}`)).status).toBe(403);
    expect((await bob.call("get", `/rooms/${room.roomId}/keys`)).status).toBe(403);
    b.ws.close();
  });

  test("ataque: o removido não volta nem com o convite antigo nem com o novo (mesma resposta do convite inválido)", async () => {
    const { body } = await remove(alice, bob);
    const old = await bob.call("post", "/joinRooms").send({ idRoom: room.roomId, key: room.inviteKey });
    const fresh = await bob.call("post", "/joinRooms").send({ idRoom: room.roomId, key: body.invite });
    const wrong = await bob.call("post", "/joinRooms").send({ idRoom: room.roomId, key: "f".repeat(32) });
    expect([old.status, fresh.status]).toEqual([403, 403]);
    expect(old.body).toEqual(wrong.body);
    expect(fresh.body).toEqual(wrong.body);
    expect(await memberIds()).toEqual([alice.id]);
  });

  test("o convite antigo deixa de valer para todos; o novo funciona", async () => {
    const { body } = await remove(alice, bob);
    expect((await carol.call("post", "/joinRooms").send({ idRoom: room.roomId, key: room.inviteKey })).status).toBe(403);
    expect((await carol.call("post", "/joinRooms").send({ idRoom: room.roomId, key: body.invite })).status).toBe(200);
  });

  test("ataque: membro que não é dono não remove (403) e nada muda", async () => {
    await join(carol, room);
    const res = await remove(bob, carol);
    expect(res.status).toBe(403);
    expect(await memberIds()).toEqual([alice.id, bob.id, carol.id]);
    expect((await roomRow()).rotation_required).toBe(false);
  });

  test("ataque: a dona não remove a si mesma (400)", async () => {
    expect((await remove(alice, alice)).status).toBe(400);
    expect(await memberIds()).toEqual([alice.id, bob.id]);
  });

  test("ataque: ninguém remove o dono, nem depois de uma transferência (o ex-dono não é mais dono)", async () => {
    expect((await transfer(alice, bob)).status).toBe(200);
    expect((await remove(alice, bob)).status).toBe(403);
    expect(await memberIds()).toEqual([alice.id, bob.id]);
  });

  test("alvo que não é membro, sala inexistente e sala alheia: a mesma resposta genérica (404)", async () => {
    const notMember = await remove(alice, carol);
    const noRoom = await alice.call("delete", `/rooms/999999/members/${bob.id}`);
    const foreign = await carol.call("delete", `/rooms/${room.roomId}/members/${bob.id}`);
    expect([notMember.status, noRoom.status, foreign.status]).toEqual([404, 404, 404]);
    expect(noRoom.body).toEqual(notMember.body);
    expect(foreign.body).toEqual(notMember.body);
  });

  test("remoção concorrente com envio: nada é gravado sem ACK, e depois da remoção o removido não grava mais", async () => {
    const b = await subscribed(bob, room.roomId);
    const sends = Array.from({ length: 15 }, (_, n) => `c${n}`);
    const removal = remove(alice, bob);
    for (const cid of sends) send(b.ws, { type: "MSG_SEND", room: room.roomId, cid, id: cid, body: fakeEnvelope() });
    expect((await removal).status).toBe(200);
    const answered = () => b.inbox.packets.filter((p) => (p.type === "MSG_ACK" && sends.includes(p.cid)) || (p.type === "ERROR" && sends.includes(p.ref)));
    for (let n = 0; n < 100 && answered().length < sends.length; n += 1) await new Promise((r) => setTimeout(r, 20));
    expect(answered()).toHaveLength(sends.length);
    const acked = b.inbox.packets.filter((p) => p.type === "MSG_ACK").map((p) => p.cid).sort();
    const saved = (await pool.query("SELECT cid FROM messages WHERE user_id = $1 ORDER BY cid", [bob.id])).rows.map((r) => r.cid);
    expect(saved).toEqual(acked);
    send(b.ws, { type: "MSG_SEND", room: room.roomId, cid: "tarde", id: "tarde", body: fakeEnvelope() });
    for (let n = 0; n < 100 && !b.inbox.packets.some((p) => p.ref === "tarde"); n += 1) await new Promise((r) => setTimeout(r, 20));
    expect(b.inbox.packets.find((p) => p.ref === "tarde")).toMatchObject({ type: "ERROR", code: "NOT_MEMBER" });
    b.ws.close();
  });
});

describe("sair (POST /rooms/:id/leave)", () => {
  test("membro sai: perde vínculo e wraps, NÃO é banido, a sala exige rotação e ele recebe REMOVED", async () => {
    const b = await connect(srv, bob.cookie);
    expect((await leave(bob)).status).toBe(200);
    expect(await nextPacket(b.inbox, "ROOM_EVENT")).toMatchObject({ room: room.roomId, kind: "REMOVED" });
    expect(await memberIds()).toEqual([alice.id]);
    expect(await wrapsOf(bob.id)).toBe(0);
    expect((await pool.query("SELECT 1 FROM room_bans WHERE user_id = $1", [bob.id])).rowCount).toBe(0);
    expect((await roomRow()).rotation_required).toBe(true);
    // Sair não bane: com o convite, volta (sem chave, pendente).
    expect((await bob.call("post", "/joinRooms").send({ idRoom: room.roomId, key: room.inviteKey })).status).toBe(200);
    b.ws.close();
  });

  test("dono com outros membros não sai sem transferir (409 OWNER_MUST_TRANSFER)", async () => {
    const res = await leave(alice);
    expect(res.status).toBe(409);
    expect(res.body).toMatchObject({ code: "OWNER_MUST_TRANSFER" });
    expect(await memberIds()).toEqual([alice.id, bob.id]);
  });

  test("sala que fica sem membros é apagada com mensagens, versões e wraps", async () => {
    await leave(bob);
    const a = await subscribed(alice, room.roomId);
    await pool.query("UPDATE rooms SET rotation_required = FALSE WHERE id = $1", [room.roomId]);
    send(a.ws, { type: "MSG_SEND", room: room.roomId, cid: "m", body: fakeEnvelope() });
    await nextPacket(a.inbox, "MSG_ACK");
    expect((await leave(alice)).status).toBe(200);
    expect((await pool.query("SELECT 1 FROM rooms WHERE id = $1", [room.roomId])).rowCount).toBe(0);
    for (const table of ["messages", "room_key_versions", "room_key_wraps", "rooms_users"]) {
      expect((await pool.query(`SELECT 1 FROM ${table} WHERE room = $1`, [room.roomId])).rowCount).toBe(0);
    }
    a.ws.close();
  });

  test("não-membro e sala inexistente: o mesmo 404", async () => {
    const foreign = await leave(carol);
    const missing = await carol.call("post", "/rooms/999999/leave");
    expect([foreign.status, missing.status]).toEqual([404, 404]);
    expect(foreign.body).toEqual(missing.body);
  });
});

describe("transferir (POST /rooms/:id/owner)", () => {
  test("Etapa 5: ROOM_EVENT OWNER_CHANGED aos inscritos e a TODAS as conexões do novo dono (para ele re-assinar o nome)", async () => {
    const a = await connect(srv, alice.cookie);
    send(a.ws, { type: "SUBSCRIBE", room: room.roomId });
    await nextPacket(a.inbox, "SUBSCRIBED");
    const b = await connect(srv, bob.cookie); // novo dono, NÃO inscrito
    expect((await transfer(alice, bob)).status).toBe(200);
    const expected = { v: 1, type: "ROOM_EVENT", room: room.roomId, kind: "OWNER_CHANGED", ownerId: bob.id };
    expect(await nextPacket(a.inbox, "ROOM_EVENT")).toEqual(expected);
    expect(await nextPacket(b.inbox, "ROOM_EVENT")).toEqual(expected);
  });


  test("a dona transfere para um membro com a chave atual; o novo dono passa a remover e a ex-dona pode sair", async () => {
    expect((await transfer(alice, bob)).status).toBe(200);
    expect((await roomRow()).owner_id).toBe(bob.id);
    expect((await leave(alice)).status).toBe(200);
    expect(await memberIds()).toEqual([bob.id]);
  });

  test("ataque: membro que não é dono não transfere para si (403)", async () => {
    expect((await transfer(bob, bob)).status).toBe(403);
    expect((await roomRow()).owner_id).toBe(alice.id);
  });

  test("destinatário sem a chave atual → 409; não-membro → 404 genérico; a si mesmo → 400", async () => {
    await join(carol, room); // entrou, mas ninguém lhe entregou a chave
    expect((await transfer(alice, carol)).status).toBe(409);
    const dave = await registerKeys(asCookie(srv, await loginUser(srv, "dave")));
    expect((await transfer(alice, dave)).status).toBe(404);
    expect((await transfer(alice, alice)).status).toBe(400);
    expect((await roomRow()).owner_id).toBe(alice.id);
  });
});

describe("concorrência: sair, remover e transferir são serializados pela sala (FOR UPDATE)", () => {
  const ownerIsMember = async () => {
    const { rows } = await pool.query(
      "SELECT r.id, EXISTS (SELECT 1 FROM rooms_users m WHERE m.room = r.id AND m.user_id = r.owner_id) AS ok FROM rooms r WHERE r.id = $1",
      [room.roomId]
    );
    return rows.length === 0 || rows[0].ok;
  };

  test("os dois últimos membros saem ao mesmo tempo: a sala some ou a dona fica (409); nunca sala sem membro", async () => {
    const [b, a] = await Promise.all([leave(bob), leave(alice)]);
    expect(b.status).toBe(200);
    expect([200, 409]).toContain(a.status);
    const exists = (await pool.query("SELECT 1 FROM rooms WHERE id = $1", [room.roomId])).rowCount === 1;
    expect(exists).toBe(a.status === 409);
    if (exists) expect(await memberIds()).toEqual([alice.id]);
  });

  test("transferir e remover o mesmo membro ao mesmo tempo: o dono é sempre membro", async () => {
    for (let n = 0; n < 5; n += 1) {
      const results = await Promise.all([transfer(alice, bob), remove(alice, bob)]);
      expect(results.filter((r) => r.status === 200)).toHaveLength(1);
      expect(await ownerIsMember()).toBe(true);
      if ((await roomRow()).owner_id !== alice.id) break;
      await pool.query("DELETE FROM room_bans WHERE room = $1", [room.roomId]);
      await pool.query("INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)", [room.roomId, bob.id]);
      await pool.query("UPDATE rooms SET rotation_required = FALSE WHERE id = $1", [room.roomId]);
      await grant(alice, room, bob);
    }
  });

  test("dono sai enquanto transfere: nunca fica sala com dono fora dela", async () => {
    const [t, l] = await Promise.all([transfer(alice, bob), leave(alice)]);
    expect(t.status).toBe(200);
    expect([200, 404, 409]).toContain(l.status);
    expect(await ownerIsMember()).toBe(true);
  });
});

describe("flag de teste E2EE_TEST_SKIP_ROTATION (só para a mutação do verify-e2ee.sh)", () => {
  const { SKIP_ROTATION_VALUE } = require("../../routes/members");
  afterEach(() => {
    delete process.env.E2EE_TEST_SKIP_ROTATION;
  });

  test("desligada por padrão: a remoção exige a rotação", async () => {
    expect(process.env.E2EE_TEST_SKIP_ROTATION).toBeUndefined();
    await remove(alice, bob);
    expect((await roomRow()).rotation_required).toBe(true);
  });

  test("qualquer valor que não seja o exato de teste não desliga nada", async () => {
    process.env.E2EE_TEST_SKIP_ROTATION = "1";
    await remove(alice, bob);
    expect((await roomRow()).rotation_required).toBe(true);
  });

  test("com o valor exato, a remoção não exige rotação nem avisa ROTATION_PENDING (a mutação que o script tem de pegar)", async () => {
    process.env.E2EE_TEST_SKIP_ROTATION = SKIP_ROTATION_VALUE;
    const a = await subscribed(alice, room.roomId);
    await remove(alice, bob);
    expect((await roomRow()).rotation_required).toBe(false);
    await expectNoPacket(a.inbox, "ROOM_EVENT");
    a.ws.close();
  });
});

describe("achados da revisão de testes (concorrência determinística)", () => {
  test("MSG_SEND espera a transação que trava a sala (FOR SHARE) e reavalia: remoção em andamento → ROTATION_PENDING, nada gravado", async () => {
    await join(carol, room);
    await grant(alice, room, carol);
    const c = await subscribed(carol, room.roomId);
    const lock = await pool.connect();
    try {
      await lock.query("BEGIN");
      await lock.query("SELECT 1 FROM rooms WHERE id = $1 FOR UPDATE", [room.roomId]);
      send(c.ws, { type: "MSG_SEND", id: "m", room: room.roomId, cid: "m", body: fakeEnvelope() });
      await expectNoPacket(c.inbox, "MSG_ACK"); // esperando o lock, não gravou do snapshot antigo
      await lock.query("UPDATE rooms SET rotation_required = TRUE WHERE id = $1", [room.roomId]);
      await lock.query("COMMIT");
    } finally {
      lock.release();
    }
    expect(await nextPacket(c.inbox, "ERROR")).toMatchObject({ code: "ROTATION_PENDING", ref: "m" });
    expect((await pool.query("SELECT 1 FROM messages WHERE room = $1", [room.roomId])).rowCount).toBe(0);
    c.ws.close();
  });

  test("entregar a chave e remover o mesmo membro ao mesmo tempo: nunca sobra wrap para quem não é membro", async () => {
    for (let n = 0; n < 5; n += 1) {
      const dave = await registerKeys(asCookie(srv, await loginUser(srv, `dave${n}`)));
      await pool.query("INSERT INTO rooms_users (room, user_id, last_msg_viewed) VALUES ($1, $2, 0)", [room.roomId, dave.id]);
      await Promise.all([grant(alice, room, dave), remove(alice, dave)]);
      const orphans = await pool.query(
        "SELECT 1 FROM room_key_wraps w WHERE w.room = $1 AND NOT EXISTS (SELECT 1 FROM rooms_users m WHERE m.room = w.room AND m.user_id = w.recipient_id)",
        [room.roomId]
      );
      expect(orphans.rowCount).toBe(0);
      await pool.query("UPDATE rooms SET rotation_required = FALSE WHERE id = $1", [room.roomId]);
    }
  });

  test("saída voluntária: quem ficou inscrito recebe ROTATION_PENDING", async () => {
    const a = await subscribed(alice, room.roomId);
    await leave(bob);
    expect(await nextPacket(a.inbox, "ROOM_EVENT")).toMatchObject({ room: room.roomId, kind: "ROTATION_PENDING" });
    a.ws.close();
  });
});
