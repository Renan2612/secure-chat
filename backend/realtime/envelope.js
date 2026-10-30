// Validação ESTRUTURAL do envelope E2EE v2 no servidor (docs/05-e2ee.md, D5),
// sem decifrar nada: o servidor não tem a chave da sala. Mesma regra do
// parseEnvelope de shared/e2ee/messages.js (tests/e2ee/envelopeParity.test.js
// confere que os dois concordam). O shared/ não entra na imagem do backend,
// por isso a regra é reescrita aqui.
//
//   exatamente {"v":2,"kv":<inteiro ≥ 1>,"iv":…,"ct":…,"sig":…,"exp":…},
//   nessa ordem e na forma canônica do JSON.stringify (sem espaços nem
//   campos extras)
//   iv: 12 bytes · sig: 64 bytes · ct: múltiplo de 128 bytes + 16 de tag,
//   entre 144 e 5904 bytes — todos em base64url canônico, sem padding
//   exp: null ou inteiro positivo (segundos Unix). Os LIMITES de tempo
//   (30 s a 7 d, retenção da sala) dependem do relógio e da sala: são
//   conferidos no MSG_SEND (realtime/handlers.js, helpers/expiry.js).
const IV_BYTES = 12;
const SIG_BYTES = 64;
const TAG_BYTES = 16;
const PAD_BLOCK = 128;
const MAX_PADDED_BYTES = 46 * PAD_BLOCK;
const KEYS = "v,kv,iv,ct,sig,exp";

const b64urlLength = (value) => {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) return -1;
  const bytes = Buffer.from(value, "base64url");
  return bytes.toString("base64url") === value ? bytes.length : -1;
};

// Devolve { kv, exp } se o body for um envelope v2 bem formado; senão null.
const parseEnvelope = (body) => {
  let env;
  try {
    env = JSON.parse(body);
  } catch {
    return null;
  }
  if (!env || typeof env !== "object" || Array.isArray(env) || Object.keys(env).join() !== KEYS) return null;
  if (env.v !== 2 || !Number.isSafeInteger(env.kv) || env.kv < 1 || env.kv > 2147483647) return null;
  if (!(env.exp === null || (Number.isSafeInteger(env.exp) && env.exp > 0))) return null;
  const padded = b64urlLength(env.ct) - TAG_BYTES;
  if (b64urlLength(env.iv) !== IV_BYTES || b64urlLength(env.sig) !== SIG_BYTES) return null;
  if (padded < PAD_BLOCK || padded % PAD_BLOCK !== 0 || padded > MAX_PADDED_BYTES) return null;
  if (JSON.stringify(env) !== body) return null;
  return { kv: env.kv, exp: env.exp };
};

module.exports = { parseEnvelope };
