// Trust store (D6): TOFU — a primeira chave pública vista de cada usuário é
// FIXADA. Se o diretório passar a devolver outra chave, o estado vira
// "changed" e o cliente recusa wraps e mensagens daquele usuário até o dono
// do trust store comparar o número de segurança e confirmar (/trust).
//
// Estados: unknown (nunca visto) · unverified (fixado, não conferido) ·
// verified (conferido pelo usuário) · changed (chave diferente da fixada).
// Funções puras sobre um objeto JSON; quem persiste é o adaptador (cifrado).
const { fingerprint } = require("./identity");

const emptyTrustStore = () => ({ v: 1, peers: {} });

const sameKeys = (a, b) => a.ecdhPub === b.ecdhPub && a.ecdsaPub === b.ecdsaPub;

const observeKeys = async (store, userId, keys, now = new Date().toISOString()) => {
  const peer = store.peers[userId];
  const entry = { ecdhPub: keys.ecdhPub, ecdsaPub: keys.ecdsaPub, fingerprint: await fingerprint(keys) };
  if (!peer) {
    return { status: "PINNED", store: { ...store, peers: { ...store.peers, [userId]: { ...entry, verified: false, pinnedAt: now } } } };
  }
  if (!peer.changed && sameKeys(peer, keys)) return { status: "MATCH", store };
  // Mudança: guarda a chave nova À PARTE; a fixada continua sendo a antiga,
  // mas nenhuma das duas é confiável até a confirmação.
  const changed = peer.changed && sameKeys(peer.changed, keys) ? peer.changed : { ...entry, seenAt: now };
  return { status: "CHANGED", store: { ...store, peers: { ...store.peers, [userId]: { ...peer, changed } } } };
};

const trustState = (store, userId, keys) => {
  const peer = store.peers[userId];
  if (!peer) return "unknown";
  if (peer.changed || !sameKeys(peer, keys)) return "changed";
  return peer.verified ? "verified" : "unverified";
};

// O usuário comparou o número de segurança: aceita a chave pendente (se
// houver) e marca como verificada.
const confirmTrust = (store, userId, now = new Date().toISOString()) => {
  const peer = store.peers[userId];
  if (!peer) throw new Error(`usuário ${userId} sem chave conhecida`);
  const { changed, ...rest } = peer;
  const pinned = changed ? { ...rest, ecdhPub: changed.ecdhPub, ecdsaPub: changed.ecdsaPub, fingerprint: changed.fingerprint, pinnedAt: now } : rest;
  return { ...store, peers: { ...store.peers, [userId]: { ...pinned, verified: true, verifiedAt: now } } };
};

module.exports = { emptyTrustStore, observeKeys, trustState, confirmTrust };
