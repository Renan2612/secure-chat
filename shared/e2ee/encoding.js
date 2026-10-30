// Codificações usadas no protocolo, sem Buffer (roda igual no navegador).
const { E2eeError } = require("./errors");

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

const utf8 = (text) => textEncoder.encode(text);
const fromUtf8 = (bytes) => textDecoder.decode(bytes);

const toB64url = (bytes) => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

// Estrito: só o alfabeto base64url, sem padding, e na forma CANÔNICA (os bits
// de sobra do último caractere precisam ser zero). Sem isso, duas strings
// diferentes decodificariam para os mesmos bytes.
const fromB64url = (text) => {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    throw new E2eeError("INVALID_ENCODING", "base64url inválido");
  }
  const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
  if (toB64url(bytes) !== text) throw new E2eeError("INVALID_ENCODING", "base64url não canônico");
  return bytes;
};

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

// JSON canônico de uma LISTA de inteiros seguros, strings e null (sem
// objetos: a ordem das chaves de um objeto não é garantida entre
// implementações). Usado em AAD, info do HKDF e nos dados assinados. O null
// (Etapa 5) é o exp de uma mensagem sem expiração: em JSON, `null` não se
// confunde com nenhum inteiro nem string.
const canonical = (items) => {
  for (const item of items) {
    if (!(item === null || typeof item === "string" || Number.isSafeInteger(item))) {
      throw new E2eeError("INVALID_CONTEXT", "contexto deve ter só inteiros, strings e null");
    }
  }
  return utf8(JSON.stringify(items));
};

module.exports = { utf8, fromUtf8, toB64url, fromB64url, concat, canonical };
