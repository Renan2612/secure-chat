// Etapa 5 (A3, correção do §4.6 de docs/06): nome da sala cifrado com a
// chave da sala E assinado pelo dono. Conteúdo cifrado = {name, seq,
// ownerId, sig}, sig = ECDSA(dono) sobre ["secure-chat/v1/room-name",
// roomId, seq, ownerId, name]. O cliente só mostra o nome com assinatura
// válida do dono ATUAL (chave fixada) e guarda o maior seq visto.
// Ataques primeiro: não-dono troca o nome (assinando com a própria chave ou
// forjando), rollback de seq, name_env de outra sala, troca de dono.
const e2ee = require("../../../shared/e2ee");

const ROOM = 7;
let alice; // dona
let mallory; // membro com a chave, não é dono
let roomKey;
let newKey;

beforeAll(async () => {
  alice = await e2ee.generateIdentity();
  alice.pub = await e2ee.exportPublicKeys(alice);
  mallory = await e2ee.generateIdentity();
  mallory.pub = await e2ee.exportPublicKeys(mallory);
  roomKey = await e2ee.generateRoomKey();
  newKey = await e2ee.generateRoomKey();
});

const ALICE = 1;
const MALLORY = 2;

const signed = (name, seq, { by = alice, ownerId = ALICE, roomId = ROOM } = {}) =>
  e2ee.signRoomName({ roomId, seq, ownerId, name, ownerEcdsaKey: by.ecdsa.privateKey });
const seal = (payload, { key = roomKey, kv = 1, roomId = ROOM } = {}) => e2ee.encryptRoomName({ roomKey: key, roomId, kv, payload });
const open = (nameEnv, { last = null, ownerId = ALICE, ownerEcdsaPub = alice.pub.ecdsaPub, keys = { 1: roomKey, 2: newKey }, roomId = ROOM } = {}) =>
  e2ee.openRoomName({ nameEnv, roomKeys: keys, roomId, ownerId, ownerEcdsaPub, last });

describe("formato", () => {
  test("ida e volta; o envelope (v2) não contém o nome e cabe em 512 bytes", async () => {
    const nameEnv = await seal(await signed("Grupo de Redes 🔐", 1));
    expect(nameEnv).not.toContain("Grupo");
    expect(new TextEncoder().encode(nameEnv).length).toBeLessThanOrEqual(512);
    expect(e2ee.parseRoomNameEnvelope(nameEnv)).toEqual({ kv: 1 });
    expect(JSON.parse(nameEnv).v).toBe(2);
    const r = await open(nameEnv);
    expect(r).toMatchObject({ name: "Grupo de Redes 🔐", verified: true, tampered: false });
    expect(r.remember).toMatchObject({ name: "Grupo de Redes 🔐", seq: 1, ownerId: ALICE });
  });

  test("o maior nome aceito (com seq e ownerId máximos) cabe; acima, recusa", async () => {
    const big = await e2ee.signRoomName({ roomId: ROOM, seq: 2147483647, ownerId: 2147483647, name: "a".repeat(e2ee.MAX_ROOM_NAME_BYTES), ownerEcdsaKey: alice.ecdsa.privateKey });
    expect(new TextEncoder().encode(await seal(big)).length).toBeLessThanOrEqual(512);
    await expect(signed("a".repeat(e2ee.MAX_ROOM_NAME_BYTES + 1), 1)).rejects.toThrow(e2ee.E2eeError);
    await expect(signed("", 1)).rejects.toThrow(e2ee.E2eeError);
    // Escapes do JSON não estouram o limite em silêncio.
    await expect(seal(await signed("\u0001".repeat(60), 1))).rejects.toMatchObject({ code: "TEXT_TOO_LONG" });
  });

  test.each([0, -1, 1.5, 2147483648])("seq inválido (%p) → recusa ao assinar", async (seq) => {
    await expect(signed("Sala", seq)).rejects.toMatchObject({ code: "INVALID_NAME" });
  });
});

describe("ataques", () => {
  test("ATAQUE: não-dono põe outro nome assinado por ELE (ownerId dele) → rejeitado; mostra o último verificado e sinaliza", async () => {
    const good = await open(await seal(await signed("Sala da Alice", 3)));
    const evil = await seal(await signed("Sala do Mallory", 4, { by: mallory, ownerId: MALLORY }), { key: newKey, kv: 2 });
    const r = await open(evil, { last: good.remember });
    expect(r).toEqual({ name: "Sala da Alice", verified: true, tampered: true, remember: null, payload: good.remember, seenSeq: 4 });
  });

  test("ATAQUE: não-dono assina com a própria chave dizendo ser o dono (ownerId da Alice) → assinatura não confere", async () => {
    const forged = await seal(await signed("Forjado", 9, { by: mallory, ownerId: ALICE }));
    expect(await open(forged)).toMatchObject({ name: null, verified: false, tampered: false, remember: null });
  });

  test("ATAQUE: assinatura adulterada (bit trocado) → rejeitado", async () => {
    const payload = await signed("Sala", 1);
    const sig = payload.sig[0] === "A" ? `B${payload.sig.slice(1)}` : `A${payload.sig.slice(1)}`;
    expect(await open(await seal({ ...payload, sig }))).toMatchObject({ name: null, verified: false });
  });

  test("ATAQUE: rollback — nome antigo VÁLIDO da dona com seq menor que o já visto → rejeitado", async () => {
    const old = await seal(await signed("Nome antigo", 1));
    const current = await open(await seal(await signed("Nome atual", 2)));
    const r = await open(old, { last: current.remember });
    expect(r).toMatchObject({ name: "Nome atual", verified: true, tampered: true, remember: null });
  });

  test("ATAQUE: mesmo seq com outro nome → rejeitado (só a dona assina, mas um cliente com bug não passa)", async () => {
    const current = await open(await seal(await signed("Nome A", 5)));
    const r = await open(await seal(await signed("Nome B", 5)), { last: current.remember });
    expect(r).toMatchObject({ name: "Nome A", tampered: true });
  });

  test("ATAQUE: o servidor troca o name_env pelo de OUTRA sala (mesma chave, mesmo dono) → o AAD amarra a sala", async () => {
    const other = await seal(await signed("Sala 8", 1, { roomId: 8 }), { roomId: 8 });
    expect(await open(other)).toMatchObject({ name: null, verified: false });
  });

  test("ATAQUE: payload assinado para outra sala, recifrado nesta → a assinatura amarra a sala", async () => {
    const elsewhere = await signed("Sala 8", 1, { roomId: 8 });
    expect(await open(await seal(elsewhere))).toMatchObject({ name: null, verified: false });
  });

  test("dono com chave não confiável (sem chave fixada) → não verificado, sem acusar adulteração", async () => {
    const r = await open(await seal(await signed("Sala", 1)), { ownerEcdsaPub: null, last: { name: "x", seq: 1, ownerId: ALICE, sig: "s" } });
    expect(r).toMatchObject({ name: null, verified: false, tampered: false });
  });
});

describe("rotação e troca de dono", () => {
  test("rotação por qualquer membro: o MESMO payload assinado, recifrado com a chave nova, continua válido", async () => {
    const payload = await signed("Sala", 2);
    const first = await open(await seal(payload));
    const rotated = await seal(first.payload, { key: newKey, kv: 2 });
    expect(await open(rotated, { last: first.remember })).toMatchObject({ name: "Sala", verified: true, tampered: false, remember: null });
  });

  test("rotação sem nome (null) → mostra o último verificado do mesmo dono; sem histórico, fallback", async () => {
    const first = await open(await seal(await signed("Sala", 1)));
    expect(await open(null, { last: first.remember })).toMatchObject({ name: "Sala", verified: true, tampered: false });
    expect(await open(null)).toMatchObject({ name: null, verified: false, tampered: false });
  });

  test("sem a chave da versão: mostra o último verificado (ou fallback), sem acusar", async () => {
    const env = await seal(await signed("Sala", 1), { key: newKey, kv: 3 });
    expect(await open(env, { keys: {} })).toMatchObject({ name: null, verified: false, tampered: false });
  });

  test("troca de dono: o nome assinado pelo dono ANTERIOR vira 'não verificado' até o novo re-assinar com seq + 1", async () => {
    const bob = await e2ee.generateIdentity();
    bob.pub = await e2ee.exportPublicKeys(bob);
    const BOB = 3;
    const before = await open(await seal(await signed("Sala", 4)));
    const asBob = { ownerId: BOB, ownerEcdsaPub: bob.pub.ecdsaPub, last: before.remember };
    const stale = await open(await seal(before.payload), asBob);
    expect(stale).toMatchObject({ name: null, verified: false, tampered: false, seenSeq: 4 });
    const resigned = await seal(await signed("Sala", 5, { by: bob, ownerId: BOB }));
    expect(await open(resigned, asBob)).toMatchObject({ name: "Sala", verified: true, remember: { seq: 5, ownerId: BOB } });
    // Re-assinar com o MESMO seq não basta (rollback em relação ao já visto).
    const sameSeq = await seal(await signed("Sala", 4, { by: bob, ownerId: BOB }));
    expect(await open(sameSeq, asBob)).toMatchObject({ verified: false });
  });
});
