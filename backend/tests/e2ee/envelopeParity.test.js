// A regra estrutural do envelope existe em dois lugares (o shared/ não entra
// na imagem do backend): shared/e2ee/messages.js (cliente) e
// backend/realtime/envelope.js (servidor). Os dois precisam concordar em
// tudo — um envelope que o cliente produz é aceito pelo servidor, e o que o
// cliente recusa o servidor também recusa.
const e2ee = require("../../../shared/e2ee");
const server = require("../../realtime/envelope");

let base;

beforeAll(async () => {
  const id = await e2ee.generateIdentity();
  const roomKey = await e2ee.generateRoomKey();
  const make = (text) =>
    e2ee.encryptMessage({ roomKey, kv: 3, roomId: 1, senderId: 1, cid: "c", text, senderEcdsaKey: id.ecdsa.privateKey });
  base = { small: JSON.parse(await make("oi")), max: JSON.parse(await make("a".repeat(e2ee.MAX_TEXT_BYTES))) };
});

const clientAccepts = (body) => {
  try {
    e2ee.parseEnvelope(body);
    return true;
  } catch {
    return false;
  }
};

const cases = () => [
  ["válido (pequeno)", JSON.stringify(base.small), true],
  ["válido (maior texto possível)", JSON.stringify(base.max), true],
  ["texto puro", "oi", false],
  ["JSON lista", "[1,2]", false],
  ["campo extra", JSON.stringify({ ...base.small, x: 1 }), false],
  ["campo faltando", JSON.stringify({ v: 1, kv: 3, iv: base.small.iv, ct: base.small.ct }), false],
  ["ordem das chaves trocada", JSON.stringify({ kv: 3, v: 1, iv: base.small.iv, ct: base.small.ct, sig: base.small.sig }), false],
  ["com espaços", JSON.stringify(base.small, null, 1), false],
  ["v = 2", JSON.stringify({ ...base.small, v: 2 }), false],
  ["kv = 0", JSON.stringify({ ...base.small, kv: 0 }), false],
  ["kv fracionário", JSON.stringify({ ...base.small, kv: 1.5 }), false],
  ["kv acima do INTEGER do Postgres", JSON.stringify({ ...base.small, kv: 2147483648 }), false],
  ["kv como texto", JSON.stringify({ ...base.small, kv: "3" }), false],
  ["iv de 11 bytes", JSON.stringify({ ...base.small, iv: e2ee.encoding.toB64url(new Uint8Array(11)) }), false],
  ["sig de 63 bytes", JSON.stringify({ ...base.small, sig: e2ee.encoding.toB64url(new Uint8Array(63)) }), false],
  ["ct sem padding", JSON.stringify({ ...base.small, ct: e2ee.encoding.toB64url(new Uint8Array(140)) }), false],
  ["ct acima do máximo", JSON.stringify({ ...base.small, ct: e2ee.encoding.toB64url(new Uint8Array(46 * 128 + 128 + 16)) }), false],
  ["ct com padding '='", JSON.stringify({ ...base.small, ct: `${base.small.ct}=` }), false],
  ["iv não canônico", JSON.stringify({ ...base.small, iv: `${base.small.iv.slice(0, 15)}B` }), null],
];

test("cliente e servidor concordam caso a caso", () => {
  for (const [label, body, expected] of cases()) {
    const c = clientAccepts(body);
    const s = server.parseEnvelope(body) !== null;
    expect({ label, client: c, server: s }).toEqual({ label, client: c, server: c });
    if (expected !== null) expect({ label, accepted: c }).toEqual({ label, accepted: expected });
  }
});

test("o servidor extrai o kv do envelope", () => {
  expect(server.parseEnvelope(JSON.stringify(base.small))).toEqual({ kv: 3 });
});
