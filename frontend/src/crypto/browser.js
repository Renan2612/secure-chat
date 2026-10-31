// Adaptador de NAVEGADOR da E2EE, equivalente ao shared/e2ee/node.js: o que
// o núcleo isomórfico não faz sozinho. Lá, arquivos 0600 fora de
// repositórios git; aqui, chaves importadas como NÃO extraíveis sempre que
// o protocolo permite (vault.js guarda tudo selado no IndexedDB).
import e2ee from "./e2ee.js";

const { fromB64url } = e2ee.encoding;
const P256 = { namedCurve: "P-256" };

// Privadas da identidade, de PKCS#8: não extraíveis (o JavaScript da página
// usa, mas não lê os bytes; uma XSS ainda as USA enquanto o cofre está
// aberto — limite em docs/07).
export const importIdentityNonExtractable = async ({ ecdhPub, ecdsaPub, ecdhPriv, ecdsaPriv }) => {
  const pub = await e2ee.importPublicKeys({ ecdhPub, ecdsaPub });
  return {
    ecdh: {
      publicKey: pub.ecdh,
      privateKey: await crypto.subtle.importKey("pkcs8", fromB64url(ecdhPriv), { name: "ECDH", ...P256 }, false, ["deriveBits"]),
    },
    ecdsa: {
      publicKey: pub.ecdsa,
      privateKey: await crypto.subtle.importKey("pkcs8", fromB64url(ecdsaPriv), { name: "ECDSA", ...P256 }, false, ["sign"]),
    },
  };
};

// A chave da SALA precisa ser extraível: o próprio cliente a embrulha para
// cada membro novo (wrapRoomKey exporta os bytes). Mesma regra do núcleo.
export const importRoomKey = (rawB64url) => e2ee.primitives.importAesKey(fromB64url(rawB64url), ["encrypt", "decrypt"], true);

export const exportRoomKey = async (roomKey) => e2ee.encoding.toB64url(await e2ee.primitives.exportRaw(roomKey));
