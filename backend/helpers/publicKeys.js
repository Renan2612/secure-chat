// Validação e fingerprint das chaves PÚBLICAS da E2EE no servidor. O
// servidor não faz criptografia de mensagens: só confere que o que entra no
// diretório é mesmo uma chave pública P-256 (SPKI) e calcula a fingerprint
// com a MESMA fórmula de shared/e2ee/identity.js (um teste confere).
const crypto = require("node:crypto");

const SPKI_B64URL = /^[A-Za-z0-9_-]{1,200}$/;
const FINGERPRINT_LABEL = "secure-chat/v1/fingerprint";

// SPKI DER de uma chave EC na curva P-256 (prime256v1). Recusa RSA, outras
// curvas, chave privada (PKCS#8) e base64 fora da forma canônica.
const isP256Spki = (value) => {
  if (typeof value !== "string" || !SPKI_B64URL.test(value)) return false;
  const der = Buffer.from(value, "base64url");
  if (der.toString("base64url") !== value) return false;
  try {
    const key = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
    return key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1";
  } catch {
    return false;
  }
};

const fingerprint = ({ ecdhPub, ecdsaPub }) =>
  crypto.createHash("sha256").update(JSON.stringify([FINGERPRINT_LABEL, ecdsaPub, ecdhPub]), "utf8").digest("hex");

module.exports = { isP256Spki, fingerprint };
