// Validação ESTRUTURAL do nome da sala cifrado (Etapa 5, A3), sem decifrar:
// o servidor não tem a chave da sala, e a assinatura do dono fica DENTRO do
// texto cifrado (quem confere é o cliente; docs/05 §12.2). Mesma regra do parseRoomNameEnvelope
// de shared/e2ee/roomName.js (tests/e2ee/roomNameParity.test.js confere).
//   exatamente {"v":2,"kv":<inteiro ≥ 1>,"iv":…,"ct":…}, nessa ordem e na
//   forma canônica; iv: 12 bytes; ct: 128 ou 256 bytes + 16 de tag; no
//   total até 512 bytes.
const MAX_NAME_ENV_BYTES = 512;
const KEYS = "v,kv,iv,ct";

const b64urlLength = (value) => {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) return -1;
  const bytes = Buffer.from(value, "base64url");
  return bytes.toString("base64url") === value ? bytes.length : -1;
};

// Devolve { kv } se for um nome cifrado bem formado; senão null.
const parseRoomNameEnvelope = (nameEnv) => {
  if (typeof nameEnv !== "string" || Buffer.byteLength(nameEnv, "utf8") > MAX_NAME_ENV_BYTES) return null;
  let env;
  try {
    env = JSON.parse(nameEnv);
  } catch {
    return null;
  }
  if (!env || typeof env !== "object" || Array.isArray(env) || Object.keys(env).join() !== KEYS) return null;
  if (env.v !== 2 || !Number.isSafeInteger(env.kv) || env.kv < 1 || env.kv > 2147483647) return null;
  const padded = b64urlLength(env.ct) - 16;
  if (b64urlLength(env.iv) !== 12 || (padded !== 128 && padded !== 256)) return null;
  if (JSON.stringify(env) !== nameEnv) return null;
  return { kv: env.kv };
};

module.exports = { parseRoomNameEnvelope, MAX_NAME_ENV_BYTES };
