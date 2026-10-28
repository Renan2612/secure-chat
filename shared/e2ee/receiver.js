// Receptor de mensagens do cliente (D5, D6): decide o que pode ser exibido.
//
//   duplicate    mesmo (remetente, cid) já aceito → ignorar (o servidor pode
//                reentregar uma mensagem antiga com outro id)
//   untrusted    chave do remetente desconhecida ou ALTERADA → recusar até o
//                usuário conferir o número de segurança e confirmar
//   missing_key  sem a chave da versão do envelope → não exibir
//   invalid      envelope, assinatura, AAD ou texto cifrado não conferem →
//                descartar e sinalizar; NUNCA exibir como válida
//   ok           { text, verified }: verified = o usuário conferiu a chave
//
// Só marca (remetente, cid) como visto DEPOIS de verificar: uma mensagem
// forjada com o mesmo cid não impede a legítima de ser aceita depois.
const { parseEnvelope, decryptMessage } = require("./messages");

const TRUSTED = new Set(["verified", "unverified"]);

// roomKeysFor(room) → { [kv]: CryptoKey }; senderKeyFor(userId) →
// { ecdsaPub, trust } com a chave FIXADA no trust store (não a do servidor).
const createReceiver = ({ roomKeysFor, senderKeyFor }) => {
  const seen = new Set();
  return {
    async accept({ room, from, cid, body }) {
      const id = `${from}:${cid}`;
      if (seen.has(id)) return { status: "duplicate" };
      let env;
      try {
        env = parseEnvelope(body);
      } catch (err) {
        return { status: "invalid", reason: err.code };
      }
      const sender = await senderKeyFor(from);
      if (!TRUSTED.has(sender?.trust)) return { status: "untrusted", trust: sender?.trust ?? "unknown" };
      const keys = await roomKeysFor(room);
      if (!keys?.[env.kv]) return { status: "missing_key", kv: env.kv };
      let text;
      try {
        text = await decryptMessage({ body, roomKeys: keys, roomId: room, senderId: from, cid, senderEcdsaPub: sender.ecdsaPub });
      } catch (err) {
        return { status: "invalid", reason: err.code ?? "INVALID_MESSAGE" };
      }
      seen.add(id);
      return { status: "ok", text, verified: sender.trust === "verified" };
    },
  };
};

module.exports = { createReceiver };
