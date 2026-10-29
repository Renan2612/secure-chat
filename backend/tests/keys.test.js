// Diretório de chaves públicas (D3). Ataques: trocar a chave de outro
// usuário, consultar chaves de quem não compartilha sala (diretório
// público), substituir a própria chave por PUT, guardar chave privada.
const nodeCrypto = require("node:crypto");
const request = require("supertest");
const e2ee = require("../../shared/e2ee");
const { app, pool, resetDb, createUser, createRoomInDb } = require("./helpers");

let alice;
let bob;
let keysA;
let keysB;

const newKeys = async () => e2ee.exportPublicKeys(await e2ee.generateIdentity());
const stored = async (userId) =>
  (await pool.query("SELECT ecdh_pub, ecdsa_pub, key_epoch FROM user_keys WHERE user_id = $1", [userId])).rows[0];

beforeAll(async () => {
  keysA = await newKeys();
  keysB = await newKeys();
});

beforeEach(async () => {
  await resetDb();
  alice = await createUser("alice");
  bob = await createUser("bob");
});

afterAll(() => pool.end());

describe("PUT /keys (registrar as próprias chaves)", () => {
  test("registra e devolve a fingerprint calculada pelo servidor (igual à do cliente)", async () => {
    const res = await alice.agent.put("/keys").send(keysA);
    expect(res.status).toBe(201);
    expect(res.body).toEqual({
      userId: alice.id,
      ...keysA,
      fingerprint: await e2ee.fingerprint(keysA),
      keyEpoch: 1,
      createdAt: expect.any(String),
    });
  });

  test("repetir com a MESMA chave é idempotente (200, nada muda)", async () => {
    await alice.agent.put("/keys").send(keysA);
    const again = await alice.agent.put("/keys").send(keysA);
    expect(again.status).toBe(200);
    expect(again.body).toMatchObject({ ...keysA, keyEpoch: 1 });
  });

  test("ataque: PUT com chave DIFERENTE é recusado (409) e a chave fixada não muda", async () => {
    await alice.agent.put("/keys").send(keysA);
    const res = await alice.agent.put("/keys").send(keysB);
    expect(res.status).toBe(409);
    expect(await stored(alice.id)).toMatchObject({ ecdh_pub: keysA.ecdhPub, ecdsa_pub: keysA.ecdsaPub, key_epoch: 1 });
  });

  test("ataque: userId no corpo é ignorado — ninguém registra chave em nome de outro", async () => {
    const res = await alice.agent.put("/keys").send({ ...keysA, userId: bob.id, user_id: bob.id });
    expect(res.status).toBe(201);
    expect(res.body.userId).toBe(alice.id);
    expect(await stored(bob.id)).toBeUndefined();
  });

  test("sem sessão → 401", async () => {
    expect((await request(app).put("/keys").send(keysA)).status).toBe(401);
  });
});

describe("validação: só chaves públicas P-256 em SPKI base64url", () => {
  const rsaSpki = () =>
    nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const p384Spki = () =>
    nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" }).publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const pkcs8 = () =>
    nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ format: "der", type: "pkcs8" }).toString("base64url");

  test.each([
    ["RSA", () => ({ ...keysA, ecdsaPub: rsaSpki() })],
    ["P-384", () => ({ ...keysA, ecdhPub: p384Spki() })],
    ["chave PRIVADA (PKCS#8) no lugar da pública", () => ({ ...keysA, ecdhPub: pkcs8() })],
    ["base64 com + e /", () => ({ ...keysA, ecdhPub: `${keysA.ecdhPub.slice(0, -2)}+/` })],
    ["lixo", () => ({ ...keysA, ecdhPub: "AAAA" })],
    ["a mesma chave nos dois papéis", () => ({ ecdhPub: keysA.ecdhPub, ecdsaPub: keysA.ecdhPub })],
    ["campo ausente", () => ({ ecdhPub: keysA.ecdhPub })],
  ])("%s → 400", async (_label, body) => {
    const res = await alice.agent.put("/keys").send(body());
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ message: "Requisição inválida" });
    expect(await stored(alice.id)).toBeUndefined();
  });

  test("campos extras (ex.: uma chave privada) são descartados, nunca gravados", async () => {
    await alice.agent.put("/keys").send({ ...keysA, ecdhPriv: pkcs8(), ecdsaPriv: pkcs8() });
    const { rows } = await pool.query("SELECT row_to_json(user_keys)::text AS row FROM user_keys");
    expect(rows[0].row).not.toMatch(/priv/i);
    expect(Object.keys((await pool.query("SELECT * FROM user_keys")).rows[0]).sort()).toEqual(
      ["created_at", "ecdh_pub", "ecdsa_pub", "fingerprint", "key_epoch", "user_id"]
    );
  });
});

describe("GET /keys/:userId (nada de diretório público)", () => {
  beforeEach(async () => {
    await alice.agent.put("/keys").send(keysA);
    await bob.agent.put("/keys").send(keysB);
  });

  test("ataque: quem NÃO compartilha sala não consulta a chave (404, sem revelar se existe)", async () => {
    const res = await bob.agent.get(`/keys/${alice.id}`);
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ message: "Não encontrado" });
    expect((await bob.agent.get("/keys/999999")).body).toEqual(res.body);
  });

  test("quem compartilha uma sala consulta", async () => {
    await createRoomInDb("Sala", [alice.id, bob.id]);
    const res = await bob.agent.get(`/keys/${alice.id}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ userId: alice.id, ...keysA, fingerprint: await e2ee.fingerprint(keysA), keyEpoch: 1 });
  });

  test("cada um consulta a própria chave", async () => {
    expect((await alice.agent.get(`/keys/${alice.id}`)).status).toBe(200);
  });

  test("compartilha sala mas o outro não tem chave → 404", async () => {
    const carol = await createUser("carol");
    await createRoomInDb("Sala", [alice.id, carol.id]);
    const res = await alice.agent.get(`/keys/${carol.id}`);
    expect(res.status).toBe(404);
    // O mesmo corpo de "não compartilha sala" e "não existe".
    expect(res.body).toEqual({ message: "Não encontrado" });
  });

  test.each(["abc", "0", "-1"])("id inválido %j → 400", async (id) => {
    expect((await alice.agent.get(`/keys/${id}`)).status).toBe(400);
  });

  test("sem sessão → 401", async () => {
    expect((await request(app).get(`/keys/${alice.id}`)).status).toBe(401);
  });
});

describe("POST /keys/reset (trocar as PRÓPRIAS chaves)", () => {
  test("substitui as chaves do próprio usuário e incrementa key_epoch", async () => {
    await alice.agent.put("/keys").send(keysA);
    const res = await alice.agent.post("/keys/reset").send(keysB);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ userId: alice.id, ...keysB, keyEpoch: 2, fingerprint: await e2ee.fingerprint(keysB) });
    expect(await stored(alice.id)).toMatchObject({ ecdh_pub: keysB.ecdhPub, key_epoch: 2 });
  });

  test("ataque: reset não alcança a chave de outro usuário (userId no corpo ignorado)", async () => {
    await alice.agent.put("/keys").send(keysA);
    await bob.agent.put("/keys").send(keysB);
    const mallory = await newKeys();
    await bob.agent.post("/keys/reset").send({ ...mallory, userId: alice.id });
    expect(await stored(alice.id)).toMatchObject({ ecdh_pub: keysA.ecdhPub, key_epoch: 1 });
    expect(await stored(bob.id)).toMatchObject({ ecdh_pub: mallory.ecdhPub, key_epoch: 2 });
  });

  test("sem chave registrada → 404 (use PUT /keys)", async () => {
    expect((await alice.agent.post("/keys/reset").send(keysA)).status).toBe(404);
  });

  test("reset com chaves inválidas → 400 e nada muda", async () => {
    await alice.agent.put("/keys").send(keysA);
    expect((await alice.agent.post("/keys/reset").send({ ...keysB, ecdhPub: "AAAA" })).status).toBe(400);
    expect(await stored(alice.id)).toMatchObject({ ecdh_pub: keysA.ecdhPub, key_epoch: 1 });
  });
});
