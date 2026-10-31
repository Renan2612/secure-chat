// C1 no cliente do navegador: quem recebe a chave da sala e quem entra numa
// rotação. Quem decide quem é membro é o SERVIDOR (adversário aqui):
// entrega automática só a VERIFICADOS; os demais só com aprovação explícita;
// CHAVE ALTERADA e removidos nunca. Número de segurança e confirmação só da
// chave que foi EXIBIDA. A rotação recifra o nome assinado pelo dono (ou
// manda null) e usa chave NOVA.
import "fake-indexeddb/auto";
import { beforeEach, describe, expect, test } from "vitest";
import e2ee from "../src/crypto/e2ee.js";
import { createVault, deleteVault } from "../src/crypto/vault.js";
import { createClient } from "../src/chat/client.js";

const ROOM = 10;
const ME = 1;

const user = async (id) => {
  const identity = await e2ee.generateIdentity();
  return { id, identity, pub: await e2ee.exportPublicKeys(identity), keyEpoch: 1, name: `u${id}` };
};

let w;

const api = async (method, path, body) => {
  w.calls.push({ method, path, body });
  const keysOf = path.match(/^\/keys\/(\d+)$/)?.[1];
  if (method === "get" && keysOf) {
    const u = w.directory[keysOf];
    return u ? { status: 200, body: { ...u.pub, keyEpoch: u.keyEpoch } } : { status: 404, body: null };
  }
  if (method === "get" && path === `/rooms/${ROOM}/keys`) return { status: 200, body: w.keys };
  if (method === "get" && path === `/rooms/${ROOM}/keys/pending`) {
    return { status: 200, body: { room: ROOM, version: w.keys.currentVersion, pending: w.pending.map((u) => ({ userId: u.id, name: u.name, keys: { ...u.pub, keyEpoch: u.keyEpoch, fingerprint: "x" } })) } };
  }
  if (method === "post" && path === `/rooms/${ROOM}/keys/wraps`) return { status: 201, body: {} };
  if (method === "get" && path === `/roomUsers/${ROOM}`) return { status: 200, body: w.members.map((u) => ({ id: u.id, name: u.name })) };
  if (method === "post" && path === `/rooms/${ROOM}/keys/rotate`) {
    w.rotated = body;
    return { status: 201, body: { room: ROOM, version: body.version } };
  }
  if (method === "get" && path === "/rooms") return { status: 200, body: [{ id: ROOM, nameEnv: w.nameEnv, ownerId: ME, retentionSeconds: null, nummessages: "0" }] };
  if (method === "delete" && path.startsWith(`/rooms/${ROOM}/members/`)) return { status: 200, body: { invite: "n".repeat(32) } };
  return { status: 404, body: null };
};

beforeEach(async () => {
  await deleteVault(ME);
  const vault = await createVault({ userId: ME, passphrase: "senha-de-cifragem-123", loginPassword: "x" });
  const [bob, carol, dave] = [await user(2), await user(3), await user(4)];
  w = { vault, bob, carol, dave, calls: [], pending: [], directory: { 1: { pub: vault.pub, keyEpoch: 1 }, 2: bob, 3: carol, 4: dave } };
  w.client = createClient({ api, me: { id: ME, name: "eu" }, vault });
  // Sala minha, v1, com a chave guardada e o nome assinado por mim.
  w.roomKey = await e2ee.generateRoomKey();
  const raw = e2ee.encoding.toB64url(await e2ee.primitives.exportRaw(w.roomKey));
  const payload = await e2ee.signRoomName({ roomId: ROOM, seq: 1, ownerId: ME, name: "Minha sala", ownerEcdsaKey: vault.identity.ecdsa.privateKey });
  w.nameEnv = await e2ee.encryptRoomName({ roomKey: w.roomKey, roomId: ROOM, kv: 1, payload });
  await vault.updateState((s) => ({ ...s, roomKeys: { [ROOM]: { 1: raw } }, rooms: { [ROOM]: { creator: ME, version: 1 } }, roomNames: { [ROOM]: payload } }));
  const wrap = await e2ee.wrapRoomKey({ roomId: ROOM, version: 1, roomKey: w.roomKey, senderId: ME, recipientId: ME, recipientEcdhPub: vault.pub.ecdhPub, senderEcdsaKey: vault.identity.ecdsa.privateKey });
  const c = await e2ee.commitRoomKey({ roomId: ROOM, version: 1, roomKey: w.roomKey, creatorEcdsaKey: vault.identity.ecdsa.privateKey });
  w.keys = { room: ROOM, currentVersion: 1, rotationRequired: false, versions: [{ version: 1, createdBy: ME, ...c }], wraps: [{ version: 1, senderId: ME, ...wrap }] };
  w.members = [{ id: ME, name: "eu" }, bob, carol];
  await w.client.ensureRoomKey(ROOM);
});

const verify = async (u) => {
  const shown = await w.client.safety(u.id);
  await w.client.confirm(u.id, shown.fingerprint);
};
const delivered = () => w.calls.filter((c) => c.path === `/rooms/${ROOM}/keys/wraps`).map((c) => c.body.recipientId);

describe("número de segurança e confirmação", () => {
  test("12 grupos de 5 dígitos, o mesmo do núcleo", async () => {
    const shown = await w.client.safety(w.bob.id);
    expect(shown.number).toMatch(/^(\d{5} ){11}\d{5}$/);
    expect(shown.number).toBe(await e2ee.safetyNumber({ userId: ME, ...w.vault.pub }, { userId: w.bob.id, ...w.bob.pub }));
    await w.client.confirm(w.bob.id, shown.fingerprint);
    expect(w.client.trustOf(w.bob.id)).toBe("verified");
  });

  test("ATAQUE: o servidor troca a chave entre a exibição e a confirmação → confirmação recusada", async () => {
    const shown = await w.client.safety(w.bob.id);
    w.directory[2] = await user(2);
    await w.client.observe(2);
    await expect(w.client.confirm(2, shown.fingerprint)).rejects.toThrow();
    expect(w.client.trustOf(2)).toBe("changed");
  });
});

describe("entrega da chave a pendentes", () => {
  test("ATAQUE: membro fantasma inserido pelo servidor (não verificado) NÃO recebe a chave sozinho; é anunciado", async () => {
    w.pending = [w.dave];
    const r = await w.client.distribute(ROOM);
    expect(delivered()).toEqual([]);
    expect(r.awaitingApproval).toEqual([expect.objectContaining({ userId: 4 })]);
  });

  test("verificado recebe automaticamente; não verificado só com aprovação explícita", async () => {
    await verify(w.bob);
    w.pending = [w.bob, w.carol];
    await w.client.distribute(ROOM);
    expect(delivered()).toEqual([2]);
    await w.client.approve(ROOM, 3);
    expect(delivered()).toEqual([2, 3]);
  });

  test("ATAQUE: CHAVE ALTERADA nunca recebe, nem com aprovação", async () => {
    await w.client.observe(3);
    w.directory[3] = await user(3);
    w.pending = [w.directory[3]];
    await w.client.distribute(ROOM);
    await expect(w.client.approve(ROOM, 3)).rejects.toThrow();
    expect(delivered()).toEqual([]);
  });
});

describe("rotação", () => {
  test("chave NOVA; só eu e os verificados ou aprovados; o nome assinado vai recifrado com a chave nova", async () => {
    await verify(w.bob);
    const r = await w.client.rotate(ROOM);
    expect(r).toMatchObject({ rotated: true, version: 2, left: [3] });
    expect(w.rotated.wraps.map((x) => x.recipientId).sort()).toEqual([1, 2]);
    const newRaw = w.vault.state.roomKeys[ROOM][2];
    expect(newRaw).not.toBe(w.vault.state.roomKeys[ROOM][1]);
    const newKey = await e2ee.primitives.importAesKey(e2ee.encoding.fromB64url(newRaw), ["encrypt", "decrypt"], true);
    const payload = await e2ee.decryptRoomName({ nameEnv: w.rotated.nameEnv, roomKeys: { 2: newKey }, roomId: ROOM });
    expect(payload).toEqual(w.vault.state.roomNames[ROOM]); // o MESMO conteúdo assinado, sem re-assinar
  });

  test("ATAQUE: removido por mim não volta numa rotação mesmo se o servidor ainda o listar", async () => {
    await verify(w.bob);
    const kicked = await w.client.kick(ROOM, 2);
    expect(kicked.invite).toBe("n".repeat(32));
    const r = await w.client.rotate(ROOM);
    expect(w.rotated.wraps.map((x) => x.recipientId)).toEqual([1]);
    expect(r.left).toContain(2);
  });

  test("sem nome assinado válido para recifrar → rotaciona com nameEnv null (fallback)", async () => {
    await w.vault.updateState((s) => ({ ...s, roomNames: {} }));
    const mallory = await user(9);
    const forged = await e2ee.signRoomName({ roomId: ROOM, seq: 5, ownerId: 9, name: "x", ownerEcdsaKey: mallory.identity.ecdsa.privateKey });
    w.nameEnv = await e2ee.encryptRoomName({ roomKey: w.roomKey, roomId: ROOM, kv: 1, payload: forged });
    await w.client.rotate(ROOM);
    expect(w.rotated.nameEnv).toBeNull();
  });
});
