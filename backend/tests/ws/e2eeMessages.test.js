// Mensagens cifradas (D5). Servidor: falha fechada sem ler o conteúdo — só
// aceita um envelope E2EE v1 estruturalmente válido e com a versão atual da
// chave. Cliente: decifra, verifica a assinatura com a chave FIXADA do
// remetente e recusa o que o servidor adulterar.
const e2ee = require("../../../shared/e2ee");
const { pool, resetDb } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, send, expectNoPacket } = require("./helpers");
const { asCookie, registerKeys, createKeyedRoom, join, grant, fetchRoomKey } = require("../e2ee/flow");

let srv;
let alice;
let bob;
let room;

const encryptAs = (user, text, cid, overrides = {}) =>
  e2ee.encryptMessage({
    roomKey: room.roomKey,
    kv: 1,
    roomId: room.roomId,
    senderId: user.id,
    cid,
    text,
    senderEcdsaKey: user.identity.ecdsa.privateKey,
    ...overrides,
  });

const subscribed = async (user) => {
  const conn = await connect(srv, user.cookie);
  send(conn.ws, { type: "SUBSCRIBE", room: room.roomId });
  await nextPacket(conn.inbox, "SUBSCRIBED");
  return conn;
};

const storedCount = async () => (await pool.query("SELECT count(*)::int AS n FROM messages")).rows[0].n;

beforeEach(async () => {
  await resetDb();
  srv = await startServer();
  alice = await registerKeys(asCookie(srv, await loginUser(srv, "alice")));
  bob = await registerKeys(asCookie(srv, await loginUser(srv, "bob")));
  room = await createKeyedRoom(alice);
  await join(bob, room);
  await grant(alice, room, bob);
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

describe("servidor: falha fechada sem decifrar", () => {
  test.each([
    ["texto puro", () => "oi, isto não está cifrado"],
    ["JSON que não é envelope", () => JSON.stringify({ text: "oi" })],
    ["envelope com campo extra (texto contrabandeado)", async () => JSON.stringify({ ...JSON.parse(await encryptAs(alice, "x", "c")), text: "oi" })],
    ["envelope fora da forma canônica", async () => JSON.stringify(JSON.parse(await encryptAs(alice, "x", "c")), null, 1)],
    ["iv com 8 bytes", async () => JSON.stringify({ ...JSON.parse(await encryptAs(alice, "x", "c")), iv: "AAAAAAAAAAA" })],
    ["sig com 32 bytes", async () => JSON.stringify({ ...JSON.parse(await encryptAs(alice, "x", "c")), sig: e2ee.encoding.toB64url(new Uint8Array(32)) })],
    ["ct sem padding (tamanho não é múltiplo de 128 + tag)", async () => JSON.stringify({ ...JSON.parse(await encryptAs(alice, "x", "c")), ct: e2ee.encoding.toB64url(new Uint8Array(100)) })],
    ["base64 com + e /", async () => JSON.stringify({ ...JSON.parse(await encryptAs(alice, "x", "c")), iv: "AAAAAAAAAAAAAA+/" })],
  ])("%s → ERROR E2EE_REQUIRED e nada gravado", async (_label, make) => {
    const { ws, inbox } = await connect(srv, alice.cookie);
    send(ws, { type: "MSG_SEND", id: "s1", room: room.roomId, cid: "c1", body: await make() });
    expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "E2EE_REQUIRED", ref: "s1" });
    expect(await storedCount()).toBe(0);
    ws.close();
  });

  test("kv diferente da versão atual da sala → ERROR KEY_VERSION_MISMATCH e nada gravado", async () => {
    const { ws, inbox } = await connect(srv, alice.cookie);
    const body = await encryptAs(alice, "oi", "c1", { kv: 2 });
    send(ws, { type: "MSG_SEND", id: "s1", room: room.roomId, cid: "c1", body });
    expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "KEY_VERSION_MISMATCH", ref: "s1" });
    expect(await storedCount()).toBe(0);
    ws.close();
  });

  test("não-membro com envelope válido continua recebendo NOT_MEMBER", async () => {
    const carol = await registerKeys(asCookie(srv, await loginUser(srv, "carol")));
    const { ws, inbox } = await connect(srv, carol.cookie);
    send(ws, { type: "MSG_SEND", room: room.roomId, cid: "c1", body: await encryptAs(carol, "oi", "c1") });
    expect(await nextPacket(inbox, "ERROR")).toMatchObject({ code: "NOT_MEMBER" });
    ws.close();
  });

  test("o banco também recusa texto puro (CHECK na coluna), mesmo fora da API", async () => {
    await expect(
      pool.query("INSERT INTO messages (room, user_id, message, cid, key_version) VALUES ($1, $2, 'oi', 'x', 1)", [room.roomId, alice.id])
    ).rejects.toThrow(/check/i);
  });
});

describe("ponta a ponta: Alice cifra, Bob decifra", () => {
  test("MSG_DELIVER traz o envelope intacto e o cid; Bob decifra com a chave da sala e a chave fixada da Alice", async () => {
    const b = await subscribed(bob);
    const a = await connect(srv, alice.cookie);
    const body = await encryptAs(alice, "MARCADOR olá Bob", "cid-1");
    send(a.ws, { type: "MSG_SEND", room: room.roomId, cid: "cid-1", body });
    const ack = await nextPacket(a.inbox, "MSG_ACK");
    const deliver = await nextPacket(b.inbox, "MSG_DELIVER");
    expect(deliver).toMatchObject({ room: room.roomId, id: ack.id, from: alice.id, cid: "cid-1", body });
    const bobKey = await fetchRoomKey(bob, room.roomId);
    const text = await e2ee.decryptMessage({
      body: deliver.body,
      roomKeys: { 1: bobKey },
      roomId: deliver.room,
      senderId: deliver.from,
      cid: deliver.cid,
      senderEcdsaPub: alice.pub.ecdsaPub,
    });
    expect(text).toBe("MARCADOR olá Bob");
    a.ws.close();
    b.ws.close();
  });

  test("histórico devolve o envelope, o cid e a versão da chave; Bob decifra", async () => {
    const a = await connect(srv, alice.cookie);
    send(a.ws, { type: "MSG_SEND", room: room.roomId, cid: "h1", body: await encryptAs(alice, "do histórico", "h1") });
    await nextPacket(a.inbox, "MSG_ACK");
    const res = await bob.call("get", `/messages/${room.roomId}`);
    expect(res.status).toBe(200);
    const [m] = res.body;
    expect(m).toMatchObject({ cid: "h1", keyversion: 1, userid: alice.id });
    const text = await e2ee.decryptMessage({
      body: m.message,
      roomKeys: { 1: await fetchRoomKey(bob, room.roomId) },
      roomId: m.roomid,
      senderId: m.userid,
      cid: m.cid,
      senderEcdsaPub: alice.pub.ecdsaPub,
    });
    expect(text).toBe("do histórico");
    a.ws.close();
  });

  test("o marcador não aparece em claro em nenhuma coluna de nenhuma tabela; o banco só tem o envelope", async () => {
    const marker = `MARCADOR-${Date.now()}`;
    const a = await connect(srv, alice.cookie);
    const body = await encryptAs(alice, marker, "m1");
    send(a.ws, { type: "MSG_SEND", room: room.roomId, cid: "m1", body });
    await nextPacket(a.inbox, "MSG_ACK");
    const { rows: tables } = await pool.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public'");
    for (const { tablename } of tables) {
      const { rows } = await pool.query(`SELECT row_to_json(t)::text AS row FROM "${tablename}" t`);
      for (const { row } of rows) expect({ tablename, leaks: row.includes(marker) }).toEqual({ tablename, leaks: false });
    }
    const { rows } = await pool.query("SELECT message, key_version FROM messages");
    expect(rows).toEqual([{ message: body, key_version: 1 }]);
    expect(() => e2ee.parseEnvelope(rows[0].message)).not.toThrow();
    a.ws.close();
  });
});

describe("servidor malicioso: o cliente percebe", () => {
  let carol;
  let deliver;
  let bobKey;

  beforeEach(async () => {
    carol = await registerKeys(asCookie(srv, await loginUser(srv, "carol")));
    await join(carol, room);
    await grant(alice, room, carol);
    const b = await subscribed(bob);
    const a = await connect(srv, alice.cookie);
    send(a.ws, { type: "MSG_SEND", room: room.roomId, cid: "orig", body: await encryptAs(alice, "transferir 10", "orig") });
    deliver = await nextPacket(b.inbox, "MSG_DELIVER");
    bobKey = await fetchRoomKey(bob, room.roomId);
    a.ws.close();
    b.ws.close();
  });

  const receiverForBob = () =>
    e2ee.createReceiver({
      roomKeysFor: async () => ({ 1: bobKey }),
      senderKeyFor: async (userId) => {
        const pub = { [alice.id]: alice.pub, [carol.id]: carol.pub }[userId];
        return pub ? { ecdsaPub: pub.ecdsaPub, trust: "unverified" } : { trust: "unknown" };
      },
    });

  test("mensagem legítima é aceita (e marcada como não verificada: TOFU sem conferência)", async () => {
    const r = await receiverForBob().accept(deliver);
    expect(r).toEqual({ status: "ok", text: "transferir 10", verified: false });
  });

  test("servidor troca o `from` (atribui à Carol) → inválida, nunca exibida", async () => {
    const r = await receiverForBob().accept({ ...deliver, from: carol.id });
    expect(r.status).toBe("invalid");
    expect(r).not.toHaveProperty("text");
  });

  test("servidor troca o `from` no banco (histórico adulterado) → inválida", async () => {
    await pool.query("UPDATE messages SET user_id = $1", [carol.id]);
    const [m] = (await bob.call("get", `/messages/${room.roomId}`)).body;
    const r = await receiverForBob().accept({ room: m.roomid, from: m.userid, cid: m.cid, body: m.message });
    expect(r.status).toBe("invalid");
  });

  test("servidor reentrega a mensagem antiga (mesmo remetente e cid, outro id) → ignorada", async () => {
    const receiver = receiverForBob();
    expect((await receiver.accept(deliver)).status).toBe("ok");
    expect(await receiver.accept({ ...deliver, id: deliver.id + 100, ts: new Date().toISOString() })).toEqual({ status: "duplicate" });
  });

  test("servidor reentrega a mensagem em OUTRA sala → inválida (sala está no AAD)", async () => {
    const r = await receiverForBob().accept({ ...deliver, room: room.roomId + 1 });
    expect(r.status).not.toBe("ok");
  });

  test("ciphertext adulterado → descartado e sinalizado", async () => {
    const env = JSON.parse(deliver.body);
    const ct = env.ct.slice(0, 10) + (env.ct[10] === "A" ? "B" : "A") + env.ct.slice(11);
    const r = await receiverForBob().accept({ ...deliver, body: JSON.stringify({ ...env, ct }) });
    expect(r.status).toBe("invalid");
  });

  test("uma mensagem inválida não 'envenena' o cid: a legítima com o mesmo cid ainda é aceita", async () => {
    const receiver = receiverForBob();
    expect((await receiver.accept({ ...deliver, from: carol.id, body: deliver.body })).status).toBe("invalid");
    expect((await receiver.accept(deliver)).status).toBe("ok");
  });

  test("remetente com CHAVE ALTERADA (trust 'changed') → recusada até confirmar", async () => {
    const receiver = e2ee.createReceiver({
      roomKeysFor: async () => ({ 1: bobKey }),
      senderKeyFor: async () => ({ ecdsaPub: alice.pub.ecdsaPub, trust: "changed" }),
    });
    expect(await receiver.accept(deliver)).toEqual({ status: "untrusted", trust: "changed" });
  });

  test("remetente verificado (número de segurança conferido) → verified: true", async () => {
    const receiver = e2ee.createReceiver({
      roomKeysFor: async () => ({ 1: bobKey }),
      senderKeyFor: async () => ({ ecdsaPub: alice.pub.ecdsaPub, trust: "verified" }),
    });
    expect(await receiver.accept(deliver)).toEqual({ status: "ok", text: "transferir 10", verified: true });
  });

  test("sem a chave da versão → missing_key (não exibe)", async () => {
    const receiver = e2ee.createReceiver({ roomKeysFor: async () => ({}), senderKeyFor: async () => ({ ecdsaPub: alice.pub.ecdsaPub, trust: "unverified" }) });
    expect(await receiver.accept(deliver)).toEqual({ status: "missing_key", kv: 1 });
  });
});

test("reenvio com o mesmo cid continua idempotente (um registro, um MSG_DELIVER)", async () => {
  const b = await subscribed(bob);
  const a = await connect(srv, alice.cookie);
  const body = await encryptAs(alice, "uma vez", "dup");
  send(a.ws, { type: "MSG_SEND", room: room.roomId, cid: "dup", body });
  const first = await nextPacket(a.inbox, "MSG_ACK");
  send(a.ws, { type: "MSG_SEND", room: room.roomId, cid: "dup", body: await encryptAs(alice, "uma vez", "dup") });
  expect((await nextPacket(a.inbox, "MSG_ACK")).id).toBe(first.id);
  await nextPacket(b.inbox, "MSG_DELIVER");
  await expectNoPacket(b.inbox, "MSG_DELIVER");
  expect(await storedCount()).toBe(1);
  a.ws.close();
  b.ws.close();
});
