// Primitivas, todas do Web Crypto (D1): nada implementado à mão.
// globalThis.crypto existe no navegador e no Node ≥ 19.
const subtle = () => {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto indisponível neste ambiente");
  return globalThis.crypto.subtle;
};

const P256 = "P-256";
const ECDH = { name: "ECDH", namedCurve: P256 };
const ECDSA = { name: "ECDSA", namedCurve: P256 };
const ECDSA_SHA256 = { name: "ECDSA", hash: "SHA-256" };
const AES_GCM = "AES-GCM";

// Todo aleatório da aplicação (IVs, chave da sala, salt do keystore) vem daqui.
const randomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

const sha256 = async (data) => new Uint8Array(await subtle().digest("SHA-256", data));

const hkdf = async (ikm, salt, info, length) => {
  const key = await subtle().importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle().deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, length * 8));
};

const pbkdf2 = async (password, salt, iterations, length) => {
  const key = await subtle().importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(
    await subtle().deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, length * 8)
  );
};

const importAesKey = (raw, usages, extractable = false) =>
  subtle().importKey("raw", raw, { name: AES_GCM }, extractable, usages);

// AES-256-GCM com tag de 128 bits; o resultado é texto cifrado || tag.
const aesGcmEncrypt = async (key, iv, plaintext, additionalData = new Uint8Array(0)) =>
  new Uint8Array(await subtle().encrypt({ name: AES_GCM, iv, additionalData }, key, plaintext));

const aesGcmDecrypt = async (key, iv, ciphertext, additionalData = new Uint8Array(0)) =>
  new Uint8Array(await subtle().decrypt({ name: AES_GCM, iv, additionalData }, key, ciphertext));

// Só para os vetores de teste conhecidos (chave crua).
const aesGcmEncryptRaw = async (rawKey, iv, plaintext, additionalData) =>
  aesGcmEncrypt(await importAesKey(rawKey, ["encrypt"]), iv, plaintext, additionalData);

// Assinatura no formato do Web Crypto: r||s (IEEE P1363), 64 bytes em P-256.
const ecdsaSign = async (privateKey, data) => new Uint8Array(await subtle().sign(ECDSA_SHA256, privateKey, data));

const ecdsaVerify = (publicKey, signature, data) => subtle().verify(ECDSA_SHA256, publicKey, signature, data);

const ecdhSecret = async (privateKey, publicKey) =>
  new Uint8Array(await subtle().deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256));

const generateEcdh = () => subtle().generateKey(ECDH, true, ["deriveBits"]);
const generateEcdsa = () => subtle().generateKey(ECDSA, true, ["sign", "verify"]);

const exportSpki = async (key) => new Uint8Array(await subtle().exportKey("spki", key));
const exportPkcs8 = async (key) => new Uint8Array(await subtle().exportKey("pkcs8", key));
const exportRaw = async (key) => new Uint8Array(await subtle().exportKey("raw", key));

const importEcdhPublic = (spki) => subtle().importKey("spki", spki, ECDH, true, []);
const importEcdsaPublic = (spki) => subtle().importKey("spki", spki, ECDSA, true, ["verify"]);
const importEcdhPrivate = (pkcs8) => subtle().importKey("pkcs8", pkcs8, ECDH, true, ["deriveBits"]);
const importEcdsaPrivate = (pkcs8) => subtle().importKey("pkcs8", pkcs8, ECDSA, true, ["sign"]);

module.exports = {
  randomBytes,
  sha256,
  hkdf,
  pbkdf2,
  importAesKey,
  aesGcmEncrypt,
  aesGcmDecrypt,
  aesGcmEncryptRaw,
  ecdsaSign,
  ecdsaVerify,
  ecdhSecret,
  generateEcdh,
  generateEcdsa,
  exportSpki,
  exportPkcs8,
  exportRaw,
  importEcdhPublic,
  importEcdsaPublic,
  importEcdhPrivate,
  importEcdsaPrivate,
};
