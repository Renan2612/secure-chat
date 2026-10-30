// MUTAÇÃO para validar o scripts/verify-e2ee.sh (MUTATION=plain-envelope): o
// cliente monta um envelope com a ESTRUTURA certa (o servidor aceita: ele só
// confere estrutura), mas com o texto preenchido em base64url no lugar do
// texto cifrado, IV e assinatura aleatórios. Carregada com `node --require`;
// o código de produção não muda.
// Esperado: o servidor grava; o destinatário recusa (não decifra) e o
// marcador aparece decodificado no banco e na captura → o verify-e2ee.sh sai
// com código != 0.
const crypto = require("crypto");
const path = require("path");
const e2ee = require(path.join(__dirname, "..", "..", "shared", "e2ee"));

e2ee.encryptMessage = async ({ kv, text, exp = null }) => {
  const data = Buffer.from(text, "utf8");
  const padded = Buffer.alloc(Math.ceil((data.length + 2) / 128) * 128);
  padded.writeUInt16BE(data.length, 0);
  data.copy(padded, 2);
  const ct = Buffer.concat([padded, Buffer.alloc(16)]); // "tag" falsa
  return JSON.stringify({
    v: 2,
    kv,
    iv: crypto.randomBytes(12).toString("base64url"),
    ct: ct.toString("base64url"),
    sig: crypto.randomBytes(64).toString("base64url"),
    exp,
  });
};
