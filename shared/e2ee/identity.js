// Identidade de um usuário (D2): um par ECDH P-256 (receber wraps da chave
// da sala) e um par ECDSA P-256 (assinar wraps e mensagens). As privadas
// nunca saem do cliente; as públicas vão ao diretório em SPKI base64url.
const p = require("./primitives");
const { toB64url, fromB64url, canonical } = require("./encoding");
const { E2eeError } = require("./errors");

const FINGERPRINT_LABEL = "secure-chat/v1/fingerprint";
const SAFETY_LABEL = "secure-chat/v1/safety";

const generateIdentity = async () => ({ ecdh: await p.generateEcdh(), ecdsa: await p.generateEcdsa() });

const exportPublicKeys = async (identity) => ({
  ecdhPub: toB64url(await p.exportSpki(identity.ecdh.publicKey)),
  ecdsaPub: toB64url(await p.exportSpki(identity.ecdsa.publicKey)),
});

// Importa e confere tipo e curva (o Web Crypto recusa SPKI de RSA, de outra
// curva ou malformado). Qualquer falha vira INVALID_KEY.
const importOne = async (importer, spkiB64url) => {
  try {
    return await importer(fromB64url(spkiB64url));
  } catch {
    throw new E2eeError("INVALID_KEY", "chave pública inválida (esperado P-256 em SPKI)");
  }
};

// Só a chave de verificação de assinaturas (ECDSA) ou só a de acordo (ECDH).
const importVerifyKey = (ecdsaPub) => importOne(p.importEcdsaPublic, ecdsaPub);
const importAgreementKey = (ecdhPub) => importOne(p.importEcdhPublic, ecdhPub);

const importPublicKeys = async ({ ecdhPub, ecdsaPub }) => ({
  ecdh: await importAgreementKey(ecdhPub),
  ecdsa: await importVerifyKey(ecdsaPub),
});

// Forma serializável para o keystore (privadas em PKCS#8): só é gravada
// cifrada (keystore.js).
const exportIdentity = async (identity) => ({
  ...(await exportPublicKeys(identity)),
  ecdhPriv: toB64url(await p.exportPkcs8(identity.ecdh.privateKey)),
  ecdsaPriv: toB64url(await p.exportPkcs8(identity.ecdsa.privateKey)),
});

const importIdentity = async (stored) => {
  const pub = await importPublicKeys(stored);
  return {
    ecdh: { publicKey: pub.ecdh, privateKey: await p.importEcdhPrivate(fromB64url(stored.ecdhPriv)) },
    ecdsa: { publicKey: pub.ecdsa, privateKey: await p.importEcdsaPrivate(fromB64url(stored.ecdsaPriv)) },
  };
};

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

// Fingerprint das duas chaves públicas de um usuário (hex do SHA-256). O
// servidor calcula a mesma coisa para a coluna user_keys.fingerprint.
const fingerprint = async ({ ecdhPub, ecdsaPub }) =>
  hex(await p.sha256(canonical([FINGERPRINT_LABEL, ecdsaPub, ecdhPub])));

// Número de segurança de um PAR de usuários (D6): SHA-256 sobre userId e as
// duas chaves públicas de cada um, em ordem canônica (menor userId
// primeiro), para os dois lados verem o mesmo número. Exibição: 12 grupos
// de 5 dígitos, cada um de 20 bits do hash reduzidos mod 100000 (240 dos
// 256 bits; o viés da redução é desprezível para comparação visual).
const safetyNumber = async (a, b) => {
  const [lo, hi] = [a, b].sort((x, y) => x.userId - y.userId);
  const digest = await p.sha256(
    canonical([SAFETY_LABEL, lo.userId, lo.ecdsaPub, lo.ecdhPub, hi.userId, hi.ecdsaPub, hi.ecdhPub])
  );
  const groups = [];
  for (let i = 0; i < 12; i += 1) {
    const bit = i * 20;
    const byte = bit >> 3;
    // 24 bits a partir do byte certo; descarta o deslocamento e fica com 20.
    const window = (digest[byte] << 16) | (digest[byte + 1] << 8) | (digest[byte + 2] ?? 0);
    const value = (window >> (4 - (bit & 7))) & 0xfffff;
    groups.push(String(value % 100000).padStart(5, "0"));
  }
  return groups.join(" ");
};

module.exports = {
  generateIdentity,
  exportPublicKeys,
  importPublicKeys,
  importVerifyKey,
  importAgreementKey,
  exportIdentity,
  importIdentity,
  fingerprint,
  safetyNumber,
};
