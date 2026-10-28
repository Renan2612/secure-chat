// Mensagem cifrada (D5). O `body` do MSG_SEND é o envelope, em JSON canônico:
//   {"v":1,"kv":<versão da chave>,"iv":b64url(12),"ct":b64url,"sig":b64url(64)}
//   texto claro = tamanho (2 bytes, big-endian) || UTF-8 || zeros, até
//                 múltiplo de 128 bytes (esconde o tamanho exato)
//   AAD = JSON canônico [1, roomId, kv, senderId, cid]
//   ct  = AES-256-GCM(chave da sala kv, iv aleatório, texto claro, AAD)
//   sig = ECDSA(remetente) sobre AAD || iv || ct
// O receptor remonta o AAD com o senderId que o SERVIDOR informou (from):
// se o servidor trocar o remetente, a assinatura (feita com a chave fixada
// de outro usuário) e a tag do GCM falham.
const p = require("./primitives");
const { utf8, fromUtf8, toB64url, fromB64url, concat, canonical } = require("./encoding");
const { importVerifyKey } = require("./identity");
const { E2eeError } = require("./errors");

const ENVELOPE_VERSION = 1;
const IV_BYTES = 12;
const SIG_BYTES = 64;
const TAG_BYTES = 16;
const PAD_BLOCK = 128;
const LENGTH_PREFIX = 2;
// Maior texto claro preenchido que ainda cabe no body de 8192 bytes do
// protocolo: 5888 + 16 de tag → 7872 caracteres base64url, mais IV,
// assinatura e o JSON (≈ 140 bytes) ficam abaixo do limite.
const MAX_PADDED_BYTES = 46 * PAD_BLOCK;
const MAX_TEXT_BYTES = MAX_PADDED_BYTES - LENGTH_PREFIX;
const ENVELOPE_KEYS = ["v", "kv", "iv", "ct", "sig"];

const pad = (text) => {
  const data = utf8(text);
  if (data.length === 0) throw new E2eeError("EMPTY_TEXT", "mensagem vazia");
  if (data.length > MAX_TEXT_BYTES) throw new E2eeError("TEXT_TOO_LONG", `mensagem acima de ${MAX_TEXT_BYTES} bytes`);
  const out = new Uint8Array(Math.ceil((data.length + LENGTH_PREFIX) / PAD_BLOCK) * PAD_BLOCK);
  out[0] = data.length >> 8;
  out[1] = data.length & 0xff;
  out.set(data, LENGTH_PREFIX);
  return out;
};

const unpad = (bytes) => {
  const length = (bytes[0] << 8) | bytes[1];
  const end = LENGTH_PREFIX + length;
  if (bytes.length % PAD_BLOCK !== 0 || length === 0 || end > bytes.length || bytes.subarray(end).some((b) => b !== 0)) {
    throw new E2eeError("INVALID_MESSAGE");
  }
  return fromUtf8(bytes.subarray(LENGTH_PREFIX, end));
};

const aadFor = ({ roomId, kv, senderId, cid }) => canonical([ENVELOPE_VERSION, roomId, kv, senderId, cid]);

const encryptMessage = async ({ roomKey, kv, roomId, senderId, cid, text, senderEcdsaKey }) => {
  const aad = aadFor({ roomId, kv, senderId, cid });
  const iv = p.randomBytes(IV_BYTES);
  const ct = await p.aesGcmEncrypt(roomKey, iv, pad(text), aad);
  const sig = await p.ecdsaSign(senderEcdsaKey, concat(aad, iv, ct));
  return JSON.stringify({ v: ENVELOPE_VERSION, kv, iv: toB64url(iv), ct: toB64url(ct), sig: toB64url(sig) });
};

// Validação ESTRUTURAL estrita (a mesma regra que o servidor aplica sem
// decifrar): exatamente as chaves v,kv,iv,ct,sig, nessa ordem e na forma
// canônica do JSON.stringify; tamanhos de iv, sig e ct coerentes com o
// padding. Qualquer desvio: INVALID_ENVELOPE.
const parseEnvelope = (body) => {
  const invalid = () => new E2eeError("INVALID_ENVELOPE", "body não é um envelope E2EE v1");
  let env;
  try {
    env = JSON.parse(body);
  } catch {
    throw invalid();
  }
  if (!env || typeof env !== "object" || Array.isArray(env)) throw invalid();
  if (Object.keys(env).join() !== ENVELOPE_KEYS.join()) throw invalid();
  if (env.v !== ENVELOPE_VERSION || !Number.isSafeInteger(env.kv) || env.kv < 1) throw invalid();
  let iv;
  let ct;
  let sig;
  try {
    iv = fromB64url(env.iv);
    ct = fromB64url(env.ct);
    sig = fromB64url(env.sig);
  } catch {
    throw invalid();
  }
  const padded = ct.length - TAG_BYTES;
  if (iv.length !== IV_BYTES || sig.length !== SIG_BYTES || padded < PAD_BLOCK || padded % PAD_BLOCK !== 0 || padded > MAX_PADDED_BYTES) {
    throw invalid();
  }
  if (JSON.stringify(env) !== body) throw invalid();
  return { v: env.v, kv: env.kv, iv, ct, sig };
};

// roomKeys: { [versão]: CryptoKey } com as chaves que este cliente tem.
// Assinatura conferida ANTES de decifrar, com a chave fixada do remetente.
const decryptMessage = async ({ body, roomKeys, roomId, senderId, cid, senderEcdsaPub }) => {
  const env = parseEnvelope(body);
  const roomKey = roomKeys[env.kv];
  if (!roomKey) throw new E2eeError("MISSING_KEY", `sem a chave da versão ${env.kv}`);
  const verifyKey = await importVerifyKey(senderEcdsaPub);
  const aad = aadFor({ roomId, kv: env.kv, senderId, cid });
  const invalid = () => new E2eeError("INVALID_MESSAGE", "mensagem não confere (assinatura, AAD ou texto cifrado)");
  if (!(await p.ecdsaVerify(verifyKey, env.sig, concat(aad, env.iv, env.ct)))) throw invalid();
  let plain;
  try {
    plain = await p.aesGcmDecrypt(roomKey, env.iv, env.ct, aad);
  } catch {
    throw invalid();
  }
  try {
    return unpad(plain);
  } catch {
    throw invalid();
  }
};

module.exports = {
  encryptMessage,
  decryptMessage,
  parseEnvelope,
  MAX_TEXT_BYTES,
  ENVELOPE: { VERSION: ENVELOPE_VERSION, IV_BYTES, SIG_BYTES, TAG_BYTES, PAD_BLOCK, MAX_PADDED_BYTES },
};
