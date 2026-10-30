// A regra estrutural do nome cifrado existe no cliente (shared/e2ee) e no
// servidor (helpers/roomName.js): os dois precisam concordar caso a caso.
const e2ee = require("../../../shared/e2ee");
const server = require("../../helpers/roomName");

let small;
let max;

beforeAll(async () => {
  const roomKey = await e2ee.generateRoomKey();
  const owner = await e2ee.generateIdentity();
  const sealed = async (name, seq) => {
    const payload = await e2ee.signRoomName({ roomId: 4, seq, ownerId: 2147483647, name, ownerEcdsaKey: owner.ecdsa.privateKey });
    return JSON.parse(await e2ee.encryptRoomName({ roomKey, roomId: 4, kv: 3, payload }));
  };
  small = await sealed("Sala", 1);
  max = await sealed("é".repeat(e2ee.MAX_ROOM_NAME_BYTES / 2), 2147483647);
});

const clientAccepts = (s) => {
  try {
    e2ee.parseRoomNameEnvelope(s);
    return true;
  } catch {
    return false;
  }
};

test("cliente e servidor concordam caso a caso", () => {
  const b64 = (n) => e2ee.encoding.toB64url(new Uint8Array(n));
  const cases = [
    ["válido (curto)", JSON.stringify(small), true],
    ["válido (maior nome)", JSON.stringify(max), true],
    ["texto puro", "Sala", false],
    ["campo extra", JSON.stringify({ ...small, name: "Sala" }), false],
    ["sem ct", JSON.stringify({ v: 1, kv: 3, iv: small.iv }), false],
    ["v = 1 (nome sem assinatura, Parte A)", JSON.stringify({ ...small, v: 1 }), false],
    ["v = 3", JSON.stringify({ ...small, v: 3 }), false],
    ["kv = 0", JSON.stringify({ ...small, kv: 0 }), false],
    ["iv de 11 bytes", JSON.stringify({ ...small, iv: b64(11) }), false],
    ["ct de 3 blocos (nome longo demais)", JSON.stringify({ ...small, ct: b64(3 * 128 + 16) }), false],
    ["ct sem padding", JSON.stringify({ ...small, ct: b64(140) }), false],
    ["com espaços", JSON.stringify(small, null, 1), false],
    ["acima de 512 bytes", JSON.stringify({ ...small, iv: `${small.iv}${"A".repeat(600)}` }), false],
  ];
  for (const [label, body, expected] of cases) {
    const c = clientAccepts(body);
    expect({ label, client: c, server: server.parseRoomNameEnvelope(body) !== null }).toEqual({ label, client: expected, server: expected });
  }
  expect(server.parseRoomNameEnvelope(JSON.stringify(small))).toEqual({ kv: 3 });
});
