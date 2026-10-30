// Mensagem cifrada (D5; v2 na Etapa 5). O `body` do MSG_SEND é o envelope,
// em JSON canônico:
//   {"v":2,"kv":<versão da chave>,"iv":b64url(12),"ct":b64url,"sig":b64url(64),"exp":<seg. Unix UTC>|null}
//   texto claro = tamanho (2 bytes, big-endian) || UTF-8 || zeros, até
//                 múltiplo de 128 bytes (esconde o tamanho exato)
//   AAD = JSON canônico [2, roomId, kv, senderId, cid, exp]
//   ct  = AES-256-GCM(chave da sala kv, iv aleatório, texto claro, AAD)
//   sig = ECDSA(remetente) sobre AAD || iv || ct
// O receptor remonta o AAD com o senderId que o SERVIDOR informou (from):
// se o servidor trocar o remetente, a assinatura (feita com a chave fixada
// de outro usuário) e a tag do GCM falham. O exp está no AAD e na
// assinatura: o servidor não consegue estender, encurtar, tirar nem pôr a
// expiração. A v1 (sem exp) deixou de ser aceita (o banco foi recriado).
const p = require("./primitives");
const { utf8, fromUtf8, toB64url, fromB64url, concat, canonical } = require("./encoding");
const { importVerifyKey } = require("./identity");
const { E2eeError } = require("./errors");

const ENVELOPE_VERSION = 2;
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
const ENVELOPE_KEYS = ["v", "kv", "iv", "ct", "sig", "exp"];
const MAX_KEY_VERSION = 2147483647;

// Expiração (A1): o servidor exige agora + 30 s <= exp <= agora + 7 d, com
// 5 min de tolerância para o relógio do cliente; o cliente descarta o que
// já venceu e o que passa do teto (remetente burlando o limite).
const MIN_TTL_SECONDS = 30;
const MAX_TTL_SECONDS = 7 * 24 * 3600;
const CLOCK_SKEW_SECONDS = 5 * 60;
const TTL_PRESETS = Object.freeze({ "1min": 60, "1h": 3600, "24h": 86400, "7d": MAX_TTL_SECONDS });
// Até 2^53 - 1 sem perda; na prática o teto é agora + 7 d.
const isExp = (exp) => exp === null || (Number.isSafeInteger(exp) && exp > 0);

// exp para um TTL em segundos (null = sem expiração), arredondado para CIMA
// no minuto: o exp vai em claro no envelope e, sem o arredondamento,
// revelaria ao servidor o segundo exato do envio (dt_message só tem minuto).
const expFor = (ttlSeconds, nowMs = Date.now()) => {
  if (ttlSeconds === null || ttlSeconds === undefined) return null;
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < MIN_TTL_SECONDS || ttlSeconds > MAX_TTL_SECONDS) {
    throw new E2eeError("INVALID_TTL", `TTL deve ficar entre ${MIN_TTL_SECONDS} s e ${MAX_TTL_SECONDS} s`);
  }
  return Math.ceil((Math.ceil(nowMs / 1000) + ttlSeconds) / 60) * 60;
};

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

const aadFor = ({ roomId, kv, senderId, cid, exp }) => canonical([ENVELOPE_VERSION, roomId, kv, senderId, cid, exp]);

const encryptMessage = async ({ roomKey, kv, roomId, senderId, cid, text, senderEcdsaKey, exp = null }) => {
  if (!isExp(exp)) throw new E2eeError("INVALID_TTL", "exp deve ser null ou segundos Unix (inteiro positivo)");
  const aad = aadFor({ roomId, kv, senderId, cid, exp });
  const iv = p.randomBytes(IV_BYTES);
  const ct = await p.aesGcmEncrypt(roomKey, iv, pad(text), aad);
  const sig = await p.ecdsaSign(senderEcdsaKey, concat(aad, iv, ct));
  return JSON.stringify({ v: ENVELOPE_VERSION, kv, iv: toB64url(iv), ct: toB64url(ct), sig: toB64url(sig), exp });
};

// Validação ESTRUTURAL estrita (a mesma regra que o servidor aplica sem
// decifrar): exatamente as chaves v,kv,iv,ct,sig,exp, nessa ordem e na
// forma canônica do JSON.stringify; tamanhos de iv, sig e ct coerentes com
// o padding; exp null ou inteiro positivo. Qualquer desvio: INVALID_ENVELOPE.
const parseEnvelope = (body) => {
  const invalid = () => new E2eeError("INVALID_ENVELOPE", "body não é um envelope E2EE v2");
  let env;
  try {
    env = JSON.parse(body);
  } catch {
    throw invalid();
  }
  if (!env || typeof env !== "object" || Array.isArray(env)) throw invalid();
  if (Object.keys(env).join() !== ENVELOPE_KEYS.join()) throw invalid();
  // kv até 2^31 - 1: o mesmo teto do servidor (INTEGER do Postgres).
  if (env.v !== ENVELOPE_VERSION || !Number.isSafeInteger(env.kv) || env.kv < 1 || env.kv > MAX_KEY_VERSION) throw invalid();
  if (!isExp(env.exp)) throw invalid();
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
  return { v: env.v, kv: env.kv, iv, ct, sig, exp: env.exp };
};

// roomKeys: { [versão]: CryptoKey } com as chaves que este cliente tem.
// Assinatura conferida ANTES de decifrar, com a chave fixada do remetente.
// Depois dela (o exp já é autêntico): vencida → EXPIRED; exp além de
// agora + 7 d + tolerância → INVALID_MESSAGE (o remetente burlou o teto).
const decryptMessage = async ({ body, roomKeys, roomId, senderId, cid, senderEcdsaPub, nowMs = Date.now() }) => {
  const env = parseEnvelope(body);
  const roomKey = roomKeys[env.kv];
  if (!roomKey) throw new E2eeError("MISSING_KEY", `sem a chave da versão ${env.kv}`);
  const verifyKey = await importVerifyKey(senderEcdsaPub);
  const aad = aadFor({ roomId, kv: env.kv, senderId, cid, exp: env.exp });
  const invalid = () => new E2eeError("INVALID_MESSAGE", "mensagem não confere (assinatura, AAD ou texto cifrado)");
  if (!(await p.ecdsaVerify(verifyKey, env.sig, concat(aad, env.iv, env.ct)))) throw invalid();
  if (env.exp !== null) {
    const now = nowMs / 1000;
    if (env.exp <= now) throw new E2eeError("EXPIRED", "mensagem expirada");
    if (env.exp > now + MAX_TTL_SECONDS + CLOCK_SKEW_SECONDS) throw invalid();
  }
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
  expFor,
  pad,
  unpad,
  MAX_TEXT_BYTES,
  MIN_TTL_SECONDS,
  MAX_TTL_SECONDS,
  CLOCK_SKEW_SECONDS,
  TTL_PRESETS,
};
