// Nome da sala cifrado (Etapa 5, A3). O servidor guarda só name_env:
//   {"v":1,"kv":<versão da chave>,"iv":b64url(12),"ct":b64url}
//   texto claro = o mesmo padding das mensagens (blocos de 128 bytes)
//   AAD = JSON canônico ["room-name", roomId, kv]
//   ct  = AES-256-GCM(chave da sala kv, iv, nome preenchido, AAD)
// Sem assinatura: qualquer um com a chave da sala poderia produzir um nome
// válido; quem PODE trocá-lo (só o dono) é regra do servidor. O AAD amarra
// o nome à sala e à versão: o servidor não troca o de uma sala pelo de
// outra. Ele ainda pode devolver um nome ANTIGO da mesma versão (docs/05).
// Vem obrigatoriamente na publicação da v1 e em cada rotação (recifrado com
// a chave nova: quem saiu não lê o nome novo).
const p = require("./primitives");
const { utf8, toB64url, fromB64url, canonical } = require("./encoding");
const { pad, unpad } = require("./messages");
const { E2eeError } = require("./errors");

const NAME_ENVELOPE_VERSION = 1;
const NAME_LABEL = "room-name";
const NAME_KEYS = ["v", "kv", "iv", "ct"];
const IV_BYTES = 12;
const TAG_BYTES = 16;
const PAD_BLOCK = 128;
const MAX_PADDED_BYTES = 2 * PAD_BLOCK;
// 256 bytes preenchidos menos os 2 do prefixo: o envelope fica abaixo dos
// 512 bytes que o servidor aceita (≈ 420 no pior caso).
const MAX_ROOM_NAME_BYTES = MAX_PADDED_BYTES - 2;
const MAX_NAME_ENV_BYTES = 512;
const MAX_KEY_VERSION = 2147483647;

const nameAad = (roomId, kv) => canonical([NAME_LABEL, roomId, kv]);

const encryptRoomName = async ({ roomKey, roomId, kv, name }) => {
  if (typeof name !== "string" || utf8(name).length > MAX_ROOM_NAME_BYTES) {
    throw new E2eeError("TEXT_TOO_LONG", `nome da sala acima de ${MAX_ROOM_NAME_BYTES} bytes`);
  }
  const iv = p.randomBytes(IV_BYTES);
  const ct = await p.aesGcmEncrypt(roomKey, iv, pad(name), nameAad(roomId, kv));
  return JSON.stringify({ v: NAME_ENVELOPE_VERSION, kv, iv: toB64url(iv), ct: toB64url(ct) });
};

// Mesma regra estrutural do servidor (backend/helpers/roomName.js).
const parseRoomNameEnvelope = (nameEnv) => {
  const invalid = () => new E2eeError("INVALID_NAME", "nome da sala cifrado malformado");
  if (typeof nameEnv !== "string" || utf8(nameEnv).length > MAX_NAME_ENV_BYTES) throw invalid();
  let env;
  try {
    env = JSON.parse(nameEnv);
  } catch {
    throw invalid();
  }
  if (!env || typeof env !== "object" || Array.isArray(env) || Object.keys(env).join() !== NAME_KEYS.join()) throw invalid();
  if (env.v !== NAME_ENVELOPE_VERSION || !Number.isSafeInteger(env.kv) || env.kv < 1 || env.kv > MAX_KEY_VERSION) throw invalid();
  let iv;
  let ct;
  try {
    iv = fromB64url(env.iv);
    ct = fromB64url(env.ct);
  } catch {
    throw invalid();
  }
  const padded = ct.length - TAG_BYTES;
  if (iv.length !== IV_BYTES || padded < PAD_BLOCK || padded % PAD_BLOCK !== 0 || padded > MAX_PADDED_BYTES) throw invalid();
  if (JSON.stringify(env) !== nameEnv) throw invalid();
  return { kv: env.kv, iv, ct };
};

const decryptRoomName = async ({ nameEnv, roomKeys, roomId }) => {
  const env = parseRoomNameEnvelope(nameEnv);
  const roomKey = roomKeys[env.kv];
  if (!roomKey) throw new E2eeError("MISSING_KEY", `sem a chave da versão ${env.kv}`);
  try {
    return unpad(await p.aesGcmDecrypt(roomKey, env.iv, env.ct, nameAad(roomId, env.kv)));
  } catch {
    throw new E2eeError("INVALID_NAME", "nome da sala não confere");
  }
};

module.exports = {
  encryptRoomName,
  decryptRoomName,
  parseRoomNameEnvelope: (nameEnv) => ({ kv: parseRoomNameEnvelope(nameEnv).kv }),
  MAX_ROOM_NAME_BYTES,
  MAX_NAME_ENV_BYTES,
};
