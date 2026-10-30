// Etapa 5 (A1): mensagens efêmeras e retenção, no servidor. Relógio
// injetado (createServer({ clock })): nada aqui depende do relógio real.
// Ataques: exp acima do máximo, já vencido, retenção da sala ignorada
// (sem exp ou exp além dela), mensagem vencida no histórico ou no banco.
const e2ee = require("../../../shared/e2ee");
const { pool, resetDb } = require("../helpers");
const { startServer, loginUser, connect, nextPacket, send, expectNoPacket } = require("./helpers");
const { asCookie, registerKeys, createKeyedRoom, join, grant } = require("../e2ee/flow");
const { createPurger } = require("../../helpers/purge");

// 2026-10-30 12:00:17 UTC (segundo "quebrado": prova o truncamento no minuto).
const START_MS = Date.UTC(2026, 9, 30, 12, 0, 17);
let nowMs = START_MS;
const clock = { nowMs: () => nowMs };
const nowSec = () => Math.floor(nowMs / 1000);

let srv;
let alice;
let bob;
let room;

const envelope = (user, cid, exp, text = "efêmera") =>
  e2ee.encryptMessage({ roomKey: room.roomKey, kv: 1, roomId: room.roomId, senderId: user.id, cid, text, senderEcdsaKey: user.identity.ecdsa.privateKey, exp });

const subscribed = async (user) => {
  const conn = await connect(srv, user.cookie);
  send(conn.ws, { type: "SUBSCRIBE", room: room.roomId });
  await nextPacket(conn.inbox, "SUBSCRIBED");
  return conn;
};

const sendAs = async (conn, user, cid, exp) => {
  send(conn.ws, { type: "MSG_SEND", id: cid, room: room.roomId, cid, body: await envelope(user, cid, exp) });
  const packet = await new Promise((resolve) => {
    const check = () => {
      const found = conn.inbox.packets.find((p) => (p.type === "MSG_ACK" && p.cid === cid) || (p.type === "ERROR" && p.ref === cid));
      if (found) resolve(found);
      else setTimeout(check, 10);
    };
    check();
  });
  return packet;
};

const stored = async () => (await pool.query("SELECT cid, expires_at, dt_message FROM messages ORDER BY id")).rows;

beforeEach(async () => {
  nowMs = START_MS;
  await resetDb();
  // O cliente cifra com o relógio REAL (Date.now) no exp: aqui o exp é
  // calculado a partir do relógio de teste, então o servidor também usa ele.
  srv = await startServer({}, { clock });
  alice = await registerKeys(asCookie(srv, await loginUser(srv, "alice")));
  bob = await registerKeys(asCookie(srv, await loginUser(srv, "bob")));
  room = await createKeyedRoom(alice);
  await join(bob, room);
  await grant(alice, room, bob);
});
afterEach(() => srv.stop());
afterAll(() => pool.end());

describe("limites do exp no MSG_SEND", () => {
  test("exp de 1 h: aceito, gravado em expires_at, entregue", async () => {
    const a = await subscribed(alice);
    const b = await subscribed(bob);
    const exp = nowSec() + 3600;
    expect(await sendAs(a, alice, "c1", exp)).toMatchObject({ type: "MSG_ACK" });
    const deliver = await nextPacket(b.inbox, "MSG_DELIVER");
    expect(JSON.parse(deliver.body).exp).toBe(exp);
    expect((await stored())[0].expires_at.getTime()).toBe(exp * 1000);
  });

  test.each([
    ["7 dias + 5 min de tolerância + 1 s", () => nowSec() + 7 * 86400 + 300 + 1],
    ["já vencido", () => nowSec() - 1],
    ["agora", () => nowSec()],
  ])("ATAQUE: exp %s → TTL_INVALID e nada gravado", async (_label, expOf) => {
    const a = await subscribed(alice);
    expect(await sendAs(a, alice, "c1", expOf())).toMatchObject({ type: "ERROR", code: "TTL_INVALID" });
    expect(await stored()).toEqual([]);
  });

  test("teto exato (7 d + 5 min) ainda passa; 10 s no futuro passa (dentro da tolerância)", async () => {
    const a = await subscribed(alice);
    expect(await sendAs(a, alice, "c1", nowSec() + 7 * 86400 + 300)).toMatchObject({ type: "MSG_ACK" });
    expect(await sendAs(a, alice, "c2", nowSec() + 10)).toMatchObject({ type: "MSG_ACK" });
  });

  test("ATAQUE: não-membro com exp inválido recebe TTL_INVALID sem tocar na sala; com exp válido, NOT_MEMBER", async () => {
    const carol = await registerKeys(asCookie(srv, await loginUser(srv, "carol")));
    const c = await connect(srv, carol.cookie);
    expect(await sendAs(c, carol, "c1", nowSec() + 30 * 86400)).toMatchObject({ code: "TTL_INVALID" });
    expect(await sendAs(c, carol, "c2", nowSec() + 3600)).toMatchObject({ code: "NOT_MEMBER" });
  });
});

describe("retenção da sala", () => {
  const setRetention = (user, retentionSeconds) =>
    user.call("put", `/rooms/${room.roomId}/retention`).send({ retentionSeconds });

  test("ATAQUE: sala com retenção, mensagem SEM exp → RETENTION_REQUIRED e nada gravado", async () => {
    expect((await setRetention(alice, 3600)).status).toBe(200);
    const b = await subscribed(bob);
    expect(await sendAs(b, bob, "c1", null)).toMatchObject({ type: "ERROR", code: "RETENTION_REQUIRED" });
    expect(await stored()).toEqual([]);
  });

  test("ATAQUE: exp além da retenção (+ tolerância) → TTL_INVALID; dentro dela passa", async () => {
    await setRetention(alice, 3600);
    const b = await subscribed(bob);
    expect(await sendAs(b, bob, "c1", nowSec() + 3600 + 300 + 1)).toMatchObject({ code: "TTL_INVALID" });
    expect(await sendAs(b, bob, "c2", nowSec() + 3600)).toMatchObject({ type: "MSG_ACK" });
    expect((await stored()).map((m) => m.cid)).toEqual(["c2"]);
  });

  test("não é retroativa: o que já estava gravado fica com o exp que tinha", async () => {
    const a = await subscribed(alice);
    await sendAs(a, alice, "antes", null);
    await setRetention(alice, 60);
    expect((await stored())[0]).toMatchObject({ cid: "antes", expires_at: null });
  });

  test("RETENTION_CHANGED vai aos inscritos, com o valor novo; remover a retenção libera exp null", async () => {
    const b = await subscribed(bob);
    await setRetention(alice, 86400);
    expect(await nextPacket(b.inbox, "ROOM_EVENT")).toEqual({ v: 1, type: "ROOM_EVENT", room: room.roomId, kind: "RETENTION_CHANGED", retentionSeconds: 86400 });
    await setRetention(alice, null);
    expect(await sendAs(b, bob, "c1", null)).toMatchObject({ type: "MSG_ACK" });
  });
});

describe("vencidas: histórico, entrega e expurgo", () => {
  test("o histórico deixa de devolver a mensagem no instante do exp, mesmo antes do expurgo", async () => {
    const a = await subscribed(alice);
    const exp = nowSec() + 60;
    await sendAs(a, alice, "curta", exp);
    await sendAs(a, alice, "longa", null);
    const history = async () => (await bob.call("get", `/messages/${room.roomId}`)).body.map((m) => m.cid);
    expect(await history()).toEqual(["curta", "longa"]);
    nowMs = exp * 1000;
    expect(await history()).toEqual(["longa"]);
    expect((await stored()).map((m) => m.cid)).toEqual(["curta", "longa"]); // ainda no banco
    // nummessages também ignora a vencida.
    expect((await bob.call("get", "/rooms")).body[0].nummessages).toBe("1");
  });

  test("o expurgo apaga do banco as vencidas (e só elas), pelo relógio do servidor", async () => {
    const a = await subscribed(alice);
    await sendAs(a, alice, "curta", nowSec() + 60);
    await sendAs(a, alice, "media", nowSec() + 3600);
    await sendAs(a, alice, "sem-exp", null);
    const purger = createPurger({ pool, clock });
    expect(await purger.purgeNow()).toBe(0);
    nowMs += 61 * 1000;
    expect(await purger.purgeNow()).toBe(1);
    expect((await stored()).map((m) => m.cid)).toEqual(["media", "sem-exp"]);
  });

  test("mutação 'servidor sem expurgo' (skip) não apaga nada — é o que o verify-e2ee.sh precisa detectar", async () => {
    const a = await subscribed(alice);
    await sendAs(a, alice, "curta", nowSec() + 60);
    nowMs += 120 * 1000;
    expect(await createPurger({ pool, clock, skip: true }).purgeNow()).toBe(0);
    expect(await stored()).toHaveLength(1);
  });

  test("o job periódico roda sozinho no intervalo", async () => {
    const a = await subscribed(alice);
    await sendAs(a, alice, "curta", nowSec() + 60);
    nowMs += 120 * 1000;
    const purger = createPurger({ pool, clock, intervalMs: 50 });
    purger.start();
    for (let i = 0; i < 40 && (await stored()).length > 0; i += 1) await new Promise((r) => setTimeout(r, 25));
    purger.stop();
    expect(await stored()).toEqual([]);
  });

  test("relógio andou durante a gravação (já vencida ao entregar) → ACK, mas sem MSG_DELIVER", async () => {
    const a = await subscribed(alice);
    const b = await subscribed(bob);
    const exp = nowSec() + 31;
    const realQuery = pool.query.bind(pool);
    jest.spyOn(pool, "query").mockImplementation(async (text, ...rest) => {
      const result = await realQuery(text, ...rest);
      if (typeof text === "string" && text.includes("INSERT INTO messages")) nowMs = exp * 1000;
      return result;
    });
    try {
      expect(await sendAs(a, alice, "c1", exp)).toMatchObject({ type: "MSG_ACK" });
      await expectNoPacket(b.inbox, "MSG_DELIVER");
    } finally {
      jest.restoreAllMocks();
    }
  });
});

describe("precisão de tempo reduzida (A4)", () => {
  test("dt_message e o ts do MSG_ACK/MSG_DELIVER só têm o minuto", async () => {
    const a = await subscribed(alice);
    const b = await subscribed(bob);
    const ack = await sendAs(a, alice, "c1", null);
    const deliver = await nextPacket(b.inbox, "MSG_DELIVER");
    for (const ts of [ack.ts, deliver.ts]) expect(ts).toMatch(/:00\.000Z$/);
    expect((await stored())[0].dt_message.getSeconds()).toBe(0);
  });
});

describe("ganchos de teste do verify-e2ee.sh (desligados por padrão)", () => {
  const { testHooksFromEnv, createTestClock, TEST_VALUE } = require("../../helpers/testHooks");
  const { purgeIntervalFromEnv } = require("../../helpers/purge");

  test("só o valor exato liga; sem variável, tudo desligado", () => {
    expect(testHooksFromEnv({})).toEqual({ testClock: false, skipPurge: false });
    for (const value of ["1", "true", "sim", `${TEST_VALUE} `]) {
      expect(testHooksFromEnv({ E2EE_TEST_CLOCK: value, E2EE_TEST_SKIP_PURGE: value })).toEqual({ testClock: false, skipPurge: false });
    }
    expect(testHooksFromEnv({ E2EE_TEST_CLOCK: TEST_VALUE, E2EE_TEST_SKIP_PURGE: TEST_VALUE })).toEqual({ testClock: true, skipPurge: true });
  });

  test("o relógio de teste só anda com advance()", () => {
    const c = createTestClock(() => 1000);
    expect(c.nowMs()).toBe(1000);
    c.advance();
    expect(c.nowMs()).toBe(1000 + 3600 * 1000);
  });

  test("PURGE_INTERVAL_MS: padrão 60 s; fora de 1 s..1 h, não sobe", () => {
    expect(purgeIntervalFromEnv(undefined)).toBe(60000);
    expect(purgeIntervalFromEnv("5000")).toBe(5000);
    for (const bad of ["999", "3600001", "abc", "-5", "1e4"]) expect(() => purgeIntervalFromEnv(bad)).toThrow();
  });
});
