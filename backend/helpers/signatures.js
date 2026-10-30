// Conferência, no servidor, das assinaturas ECDSA de uma rotação da chave da
// sala (Etapa 4b-2, D3). O servidor não abre wraps nem vê a chave: ele só
// confirma, com a chave pública registrada do autor, que cada wrap e o
// compromisso foram assinados por quem está rotacionando e para o contexto
// certo (sala, versão, destinatário). Os clientes conferem de novo com a
// chave FIXADA no trust store; isto é uma barreira a mais, não a única.
//
// Mesmos rótulos e dados assinados de shared/e2ee/roomKeys.js (o shared/
// não entra na imagem do backend); rotation.test.js prova a paridade, já que
// os corpos válidos são montados com o núcleo do cliente.
const crypto = require("node:crypto");

const WRAP_SIG_LABEL = "secure-chat/v1/wrap-sig";
const COMMIT_SIG_LABEL = "secure-chat/v1/key-commitment-sig";

// A chave do autor vem do diretório (validada no PUT /keys): se ela não
// importa, o banco está corrompido — erro do servidor (500, com log), não
// "assinatura inválida". Assinatura malformada é só inválida (false).
const verify = (ecdsaPubB64url, items, sigB64url) => {
  const key = crypto.createPublicKey({ key: Buffer.from(ecdsaPubB64url, "base64url"), format: "der", type: "spki" });
  const data = Buffer.from(JSON.stringify(items), "utf8");
  try {
    return crypto.verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, Buffer.from(sigB64url, "base64url"));
  } catch {
    return false;
  }
};

const verifyWrapSig = (ecdsaPub, { roomId, version, recipientId, senderId }, wrap) =>
  verify(ecdsaPub, [WRAP_SIG_LABEL, roomId, version, recipientId, senderId, wrap.ephPub, wrap.iv, wrap.wrapped], wrap.sig);

const verifyCommitmentSig = (ecdsaPub, { roomId, version, commitment }, commitmentSig) =>
  verify(ecdsaPub, [COMMIT_SIG_LABEL, roomId, version, commitment], commitmentSig);

module.exports = { verifyWrapSig, verifyCommitmentSig };
