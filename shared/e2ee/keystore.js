// Cofre de dados do cliente (D2): JSON cifrado com AES-256-GCM sob uma chave
// derivada por PBKDF2-SHA-256 da "senha de cifragem" — DISTINTA da senha de
// login, que vai ao servidor. Usado para a identidade (chaves privadas), as
// chaves de sala recebidas e o trust store.
//
// O cabeçalho (versão, iterações, salt) entra no AAD: editar o arquivo para
// rebaixar o custo do PBKDF2 faz a abertura falhar. Sem recuperação: perdeu
// a senha de cifragem ou o arquivo, perdeu as chaves (docs/05-e2ee.md).
const p = require("./primitives");
const { utf8, fromUtf8, toB64url, fromB64url, canonical } = require("./encoding");
const { E2eeError } = require("./errors");

const FORMAT = "secure-chat-keystore";
const VERSION = 1;
const MIN_ITERATIONS = 600000; // recomendação OWASP (2023) para PBKDF2-SHA-256
const MIN_PASSPHRASE_CHARS = 10;
const SALT_BYTES = 16;
const IV_BYTES = 12;

const headerAad = (iterations, salt) => canonical([`secure-chat/v${VERSION}/keystore`, VERSION, iterations, salt]);

const deriveKey = async (passphrase, saltBytes, iterations) =>
  p.importAesKey(await p.pbkdf2(utf8(passphrase), saltBytes, iterations, 32), ["encrypt", "decrypt"]);

const sealJson = async (passphrase, data, { iterations = MIN_ITERATIONS } = {}) => {
  if (typeof passphrase !== "string" || [...passphrase].length < MIN_PASSPHRASE_CHARS) {
    throw new E2eeError("WEAK_PASSPHRASE", `a senha de cifragem precisa de pelo menos ${MIN_PASSPHRASE_CHARS} caracteres`);
  }
  if (!Number.isSafeInteger(iterations) || iterations < MIN_ITERATIONS) {
    throw new E2eeError("WEAK_KDF", `PBKDF2 exige pelo menos ${MIN_ITERATIONS} iterações`);
  }
  const salt = toB64url(p.randomBytes(SALT_BYTES));
  const iv = p.randomBytes(IV_BYTES);
  const key = await deriveKey(passphrase, fromB64url(salt), iterations);
  const ct = await p.aesGcmEncrypt(key, iv, utf8(JSON.stringify(data)), headerAad(iterations, salt));
  return { format: FORMAT, v: VERSION, kdf: { name: "PBKDF2-SHA-256", iterations, salt }, iv: toB64url(iv), ct: toB64url(ct) };
};

// Senha errada e arquivo adulterado são indistinguíveis (a tag do GCM não
// confere): os dois viram BAD_PASSPHRASE.
const openJson = async (passphrase, sealed) => {
  const kdf = sealed?.kdf;
  if (sealed?.format !== FORMAT || sealed.v !== VERSION || kdf?.name !== "PBKDF2-SHA-256") {
    throw new E2eeError("INVALID_KEYSTORE", "arquivo não é um keystore do secure-chat v1");
  }
  if (!Number.isSafeInteger(kdf.iterations) || kdf.iterations < MIN_ITERATIONS) {
    throw new E2eeError("WEAK_KDF", `keystore com menos de ${MIN_ITERATIONS} iterações de PBKDF2`);
  }
  try {
    const key = await deriveKey(passphrase, fromB64url(kdf.salt), kdf.iterations);
    const plain = await p.aesGcmDecrypt(key, fromB64url(sealed.iv), fromB64url(sealed.ct), headerAad(kdf.iterations, kdf.salt));
    return JSON.parse(fromUtf8(plain));
  } catch {
    throw new E2eeError("BAD_PASSPHRASE", "senha de cifragem errada ou arquivo adulterado");
  }
};

module.exports = { sealJson, openJson };
