// Cliente E2EE do navegador (src/chat/client.js) contra uma API FALSA em
// memória: o servidor aqui é o adversário (D2 da 4b-1). Ataques primeiro:
// versão da chave rebaixada, criador trocado, wrap com chave falsa
// (compromisso), v2 trocada por quem não foi verificado, chave alterada do
// remetente, nome assinado por quem não é o dono, mensagem vencida.
import "fake-indexeddb/auto";
import { beforeEach, describe, expect, test } from "vitest";
import e2ee from "../src/crypto/e2ee.js";
import { createVault, deleteVault } from "../src/crypto/vault.js";
import { createClient } from "../src/chat/client.js";

const ROOM = 10;
const ALICE = 1;
const BOB = 2;
const MALLORY = 3;

let world;

const identityOf = async (id) => {
  const identity = await e2ee.generateIdentity();
  return { id, identity, pub: await e2ee.exportPublicKeys(identity), keyEpoch: 1 };
};

// Servidor falso: só o necessário para as rotas que o cliente usa.
const fakeApi = (w) => {
  const calls = [];
  const api = async (method, path, body) => {
    calls.push({ method, path, body });
    const user = path.match(/^\/keys\/(\d+)$/)?.[1];
    if (method === "get" && user) {
      const u = w.directory[user];
      return u ? { status: 200, body: { ...u.pub, keyEpoch: u.keyEpoch } } : { status: 404, body: { message: "Não encontrado" } };
    }
    if (method === "put" && path === "/keys") return { status: 201, body: { keyEpoch: 1 } };
    if (method === "post" && path === "/createRoom") return { status: 201, body: { id: ROOM, key: "c".repeat(32) } };
    if (method === "post" && path === `/rooms/${ROOM}/keys`) {
      w.published = body;
      return { status: 201, body: { room: ROOM, version: 1 } };
    }
    if (method === "get" && path === `/rooms/${ROOM}/keys`) return { status: 200, body: w.keys };
    if (method === "delete" && path === `/rooms/${ROOM}/keys/wraps/mine`) return { status: 204, body: null };
    if (method === "get" && path === "/rooms") return { status: 200, body: w.rooms };
    return { status: 404, body: null };
  };
  api.calls = calls;
  return api;
};

beforeEach(async () => {
  await deleteVault(ALICE);
  const vault = await createVault({ userId: ALICE, passphrase: "senha-de-cifragem-123", loginPassword: "outra" });
  const bob = await identityOf(BOB);
  const mallory = await identityOf(MALLORY);
  world = { vault, bob, mallory, directory: { [BOB]: bob, [MALLORY]: mallory, [ALICE]: { pub: vault.pub, keyEpoch: 1 } } };
  world.api = fakeApi(world);
  world.client = createClient({ api: world.api, me: { id: ALICE, name: "alice" }, vault });
});

// Bob cria a sala (v1) e entrega a chave à Alice: o que o servidor devolveria.
const bobsRoom = async ({ roomKey = null, commitWith = null, creator = BOB } = {}) => {
  const key = roomKey ?? (await e2ee.generateRoomKey());
  const ctx = { roomId: ROOM, version: 1 };
  const wrap = await e2ee.wrapRoomKey({ ...ctx, roomKey: key, senderId: BOB, recipientId: ALICE, recipientEcdhPub: world.vault.pub.ecdhPub, senderEcdsaKey: world.bob.identity.ecdsa.privateKey });
  const committed = await e2ee.commitRoomKey({ ...ctx, roomKey: commitWith ?? key, creatorEcdsaKey: world.bob.identity.ecdsa.privateKey });
  world.keys = {
    room: ROOM,
    currentVersion: 1,
    rotationRequired: false,
    versions: [{ version: 1, createdBy: creator, ...committed }],
    wraps: [{ version: 1, senderId: BOB, ...wrap }],
  };
  return key;
};

describe("criar sala", () => {
  test("o nome NÃO vai em claro: só cifrado e assinado por mim (seq 1); a chave fica no cofre", async () => {
    const created = await world.client.createRoom("Sala Secreta");
    expect(created).toEqual({ id: ROOM, invite: "c".repeat(32) });
    expect(world.api.calls.find((c) => c.path === "/createRoom").body).toEqual({});
    expect(JSON.stringify(world.published)).not.toContain("Secreta");
    const roomKey = await e2ee.primitives.importAesKey(e2ee.encoding.fromB64url(world.vault.state.roomKeys[ROOM][1]), ["encrypt", "decrypt"], true);
    const r = await e2ee.openRoomName({ nameEnv: world.published.nameEnv, roomKeys: { 1: roomKey }, roomId: ROOM, ownerId: ALICE, ownerEcdsaPub: world.vault.pub.ecdsaPub });
    expect(r).toMatchObject({ name: "Sala Secreta", verified: true });
    expect(world.vault.state.roomNames[ROOM]).toMatchObject({ seq: 1, ownerId: ALICE });
    expect(world.vault.state.rooms[ROOM]).toEqual({ creator: ALICE, version: 1 });
  });

  test("nome acima de 100 bytes é recusado antes de qualquer requisição", async () => {
    await expect(world.client.createRoom("é".repeat(51))).rejects.toMatchObject({ code: "TEXT_TOO_LONG" });
    expect(world.api.calls).toEqual([]);
  });
});

describe("chave da sala (servidor adversário)", () => {
  test("wrap legítimo do criador: aceito, guardado, criador e versão fixados (TOFU por sala)", async () => {
    await bobsRoom();
    expect(await world.client.ensureRoomKey(ROOM)).toMatchObject({ ok: true, sender: BOB });
    expect(world.client.hasCurrentKey(ROOM)).toBe(true);
    expect(world.vault.state.rooms[ROOM]).toEqual({ creator: BOB, version: 1 });
  });

  test("ATAQUE: wrap com chave FALSA (não confere com o compromisso do criador) → recusado e descartado no servidor", async () => {
    await bobsRoom({ commitWith: await e2ee.generateRoomKey() });
    expect(await world.client.ensureRoomKey(ROOM)).toMatchObject({ ok: false });
    expect(world.client.hasCurrentKey(ROOM)).toBe(false);
    expect(world.api.calls.some((c) => c.method === "delete" && c.path === `/rooms/${ROOM}/keys/wraps/mine`)).toBe(true);
  });

  test("ATAQUE: o servidor rebaixa a versão abaixo da já vista → recusado", async () => {
    await bobsRoom();
    await world.client.ensureRoomKey(ROOM);
    await world.vault.saveState({ ...world.vault.state, rooms: { [ROOM]: { creator: BOB, version: 3 } } });
    expect(await world.client.ensureRoomKey(ROOM)).toMatchObject({ ok: false, reason: "VERSION_ROLLBACK" });
  });

  test("ATAQUE: o servidor troca o criador da v1 depois de fixado → recusado", async () => {
    await bobsRoom();
    await world.client.ensureRoomKey(ROOM);
    const state = world.vault.state;
    await world.vault.saveState({ ...state, roomKeys: {} });
    world.keys.versions[0].createdBy = MALLORY;
    expect(await world.client.ensureRoomKey(ROOM)).toMatchObject({ ok: false });
    expect(world.client.hasCurrentKey(ROOM)).toBe(false);
  });

  test("ATAQUE: v2 trocada por quem NÃO foi verificado → não aceita (o servidor poderia inserir uma conta)", async () => {
    const v1 = await bobsRoom();
    await world.client.ensureRoomKey(ROOM);
    const v2 = await e2ee.generateRoomKey();
    const ctx = { roomId: ROOM, version: 2 };
    const wrap = await e2ee.wrapRoomKey({ ...ctx, roomKey: v2, senderId: MALLORY, recipientId: ALICE, recipientEcdhPub: world.vault.pub.ecdhPub, senderEcdsaKey: world.mallory.identity.ecdsa.privateKey });
    world.keys.currentVersion = 2;
    world.keys.versions.push({ version: 2, createdBy: MALLORY, ...(await e2ee.commitRoomKey({ ...ctx, roomKey: v2, creatorEcdsaKey: world.mallory.identity.ecdsa.privateKey })) });
    world.keys.wraps.push({ version: 2, senderId: MALLORY, ...wrap });
    expect(await world.client.ensureRoomKey(ROOM)).toMatchObject({ ok: false });
    expect(Object.keys(world.vault.state.roomKeys[ROOM])).toEqual(["1"]);
    expect(v1).toBeDefined();
  });
});

describe("mensagens", () => {
  const packetFrom = async (sender, roomKey, { cid = "c1", text = "oi", exp = null } = {}) => ({
    room: ROOM,
    from: sender.id,
    cid,
    id: 1,
    ts: "2026-10-31T10:00:00.000Z",
    body: await e2ee.encryptMessage({ roomKey, kv: 1, roomId: ROOM, senderId: sender.id, cid, text, senderEcdsaKey: sender.identity.ecdsa.privateKey, exp }),
  });

  test("mensagem do Bob: ok, não verificado (TOFU); a reentrega é duplicata", async () => {
    const key = await bobsRoom();
    await world.client.ensureRoomKey(ROOM);
    const packet = await packetFrom(world.bob, key);
    expect(await world.client.accept(packet)).toMatchObject({ status: "ok", text: "oi", verified: false });
    expect(await world.client.accept({ ...packet, id: 99 })).toEqual({ status: "duplicate" });
  });

  test("ATAQUE: o servidor atribui a mensagem do Bob ao Mallory (from trocado) → inválida", async () => {
    const key = await bobsRoom();
    await world.client.ensureRoomKey(ROOM);
    const packet = await packetFrom(world.bob, key);
    expect((await world.client.accept({ ...packet, from: MALLORY })).status).toBe("invalid");
  });

  test("ATAQUE: o diretório troca a chave do Bob → CHAVE ALTERADA, mensagem recusada", async () => {
    const key = await bobsRoom();
    await world.client.ensureRoomKey(ROOM);
    world.directory[BOB] = await identityOf(BOB);
    const forged = await packetFrom(world.directory[BOB], key, { cid: "c2" });
    expect(await world.client.accept(forged)).toMatchObject({ status: "untrusted", trust: "changed" });
  });

  test("vencida: expired (não exibe)", async () => {
    const key = await bobsRoom();
    await world.client.ensureRoomKey(ROOM);
    const packet = await packetFrom(world.bob, key, { exp: Math.floor(Date.now() / 1000) - 1 });
    expect(await world.client.accept(packet)).toEqual({ status: "expired" });
  });

  test("sem a chave da versão: missing_key", async () => {
    const key = await bobsRoom();
    const packet = await packetFrom(world.bob, key);
    world.keys.wraps = [];
    expect((await world.client.accept(packet)).status).toBe("missing_key");
  });
});

describe("nome da sala na lista", () => {
  const listed = async (signer, ownerId, seq = 1) => {
    const key = await bobsRoom();
    await world.client.ensureRoomKey(ROOM);
    const payload = await e2ee.signRoomName({ roomId: ROOM, seq, ownerId: signer.id, name: `Sala de ${signer.id}`, ownerEcdsaKey: signer.identity.ecdsa.privateKey });
    world.rooms = [{ id: ROOM, nameEnv: await e2ee.encryptRoomName({ roomKey: key, roomId: ROOM, kv: 1, payload }), retentionSeconds: null, ownerId, nummessages: "0" }];
    return world.client.listRooms();
  };

  test("assinado pelo dono atual (chave fixada): mostra e guarda o seq no cofre", async () => {
    expect((await listed(world.bob, BOB, 4))[0]).toMatchObject({ id: ROOM, name: `Sala de ${BOB}`, nameVerified: true });
    expect(world.vault.state.roomNames[ROOM].seq).toBe(4);
  });

  test("ATAQUE: assinado por quem não é o dono → 'nome não verificado' (name null)", async () => {
    expect((await listed(world.mallory, BOB))[0]).toMatchObject({ id: ROOM, name: null, nameVerified: false });
  });

  test("sala sem a chave ainda: name null (Sala #id), sem erro", async () => {
    world.rooms = [{ id: 77, nameEnv: null, retentionSeconds: null, ownerId: BOB, nummessages: "0" }];
    expect(await world.client.listRooms()).toEqual([expect.objectContaining({ id: 77, name: null, nameVerified: false })]);
  });
});
