// Chave da sala (D4): AES-256 aleatória, gerada no cliente do criador, e
// entregue a cada membro como um "wrap" que só ele abre.
//
// Wrap para o destinatário R, enviado por S:
//   par efêmero E (novo a cada wrap) · segredo = ECDH(E.priv, R.ecdhPub)
//   KEK  = HKDF-SHA-256(segredo, salt = SPKI(E.pub),
//                       info = ["secure-chat/v1/wrap", roomId, versão, R])
//   wrapped = AES-256-GCM(KEK, iv, chave crua, AAD = [rótulo, roomId, versão, R, S])
//   sig  = ECDSA(S.ecdsaPriv, [rótulo-sig, roomId, versão, R, S, E.pub, iv, wrapped])
// O servidor guarda o wrap, mas sem a privada ECDH de R não deriva a KEK.
//
// Compromisso da chave (contra um MEMBRO que entregue a um novato um wrap
// válido, assinado por ele, mas com OUTRA chave): o criador publica com a
// versão  commitment = SHA-256(["secure-chat/v1/key-commitment", sala, versão] || chave)
// e o assina. Quem abre um wrap confere a chave obtida contra o compromisso
// (com a chave FIXADA do criador) antes de usá-la.
const p = require("./primitives");
const { toB64url, fromB64url, concat, canonical } = require("./encoding");
const { importAgreementKey, importVerifyKey } = require("./identity");
const { E2eeError } = require("./errors");

const WRAP_LABEL = "secure-chat/v1/wrap";
const WRAP_SIG_LABEL = "secure-chat/v1/wrap-sig";
const COMMIT_LABEL = "secure-chat/v1/key-commitment";
const COMMIT_SIG_LABEL = "secure-chat/v1/key-commitment-sig";
const ROOM_KEY_BYTES = 32;
const IV_BYTES = 12;
const SIG_BYTES = 64;
const WRAPPED_BYTES = ROOM_KEY_BYTES + 16; // + tag do GCM

// Chave crua de getRandomValues (D1), importada para AES-GCM. Extraível
// porque o próprio cliente precisa embrulhá-la para os novos membros.
const generateRoomKey = () => p.importAesKey(p.randomBytes(ROOM_KEY_BYTES), ["encrypt", "decrypt"], true);

const signedData = ({ roomId, version, recipientId, senderId }, ephPub, iv, wrapped) =>
  canonical([WRAP_SIG_LABEL, roomId, version, recipientId, senderId, ephPub, iv, wrapped]);

const deriveKek = async (secret, ephSpki, { roomId, version, recipientId }, usage) =>
  p.importAesKey(await p.hkdf(secret, ephSpki, canonical([WRAP_LABEL, roomId, version, recipientId]), 32), [usage]);

const wrapAad = ({ roomId, version, recipientId, senderId }) =>
  canonical([WRAP_LABEL, roomId, version, recipientId, senderId]);

const wrapRoomKey = async ({ roomKey, roomId, version, senderId, recipientId, recipientEcdhPub, senderEcdsaKey }) => {
  const ctx = { roomId, version, recipientId, senderId };
  const recipient = await importAgreementKey(recipientEcdhPub);
  const eph = await p.generateEcdh();
  const ephSpki = await p.exportSpki(eph.publicKey);
  const kek = await deriveKek(await p.ecdhSecret(eph.privateKey, recipient), ephSpki, ctx, "encrypt");
  const iv = p.randomBytes(IV_BYTES);
  const wrappedBytes = await p.aesGcmEncrypt(kek, iv, await p.exportRaw(roomKey), wrapAad(ctx));
  const wrap = { ephPub: toB64url(ephSpki), iv: toB64url(iv), wrapped: toB64url(wrappedBytes) };
  const sig = await p.ecdsaSign(senderEcdsaKey, signedData(ctx, wrap.ephPub, wrap.iv, wrap.wrapped));
  return { ...wrap, sig: toB64url(sig) };
};

// Confere a assinatura com a chave ECDSA FIXADA do remetente ANTES de
// qualquer outra coisa; depois deriva a KEK e abre. Qualquer falha:
// INVALID_WRAP (sem dizer qual etapa falhou).
const unwrapRoomKey = async ({ wrap, roomId, version, senderId, recipientId, recipientEcdhKey, senderEcdsaPub }) => {
  const ctx = { roomId, version, recipientId, senderId };
  const invalid = () => new E2eeError("INVALID_WRAP", "wrap da chave da sala inválido");
  const verifyKey = await importVerifyKey(senderEcdsaPub);
  let iv;
  let wrapped;
  let sig;
  let eph;
  try {
    iv = fromB64url(wrap.iv);
    wrapped = fromB64url(wrap.wrapped);
    sig = fromB64url(wrap.sig);
    if (iv.length !== IV_BYTES || wrapped.length !== WRAPPED_BYTES || sig.length !== SIG_BYTES) throw invalid();
    if (!(await p.ecdsaVerify(verifyKey, sig, signedData(ctx, wrap.ephPub, wrap.iv, wrap.wrapped)))) throw invalid();
    eph = await importAgreementKey(wrap.ephPub);
  } catch {
    throw invalid();
  }
  try {
    const kek = await deriveKek(await p.ecdhSecret(recipientEcdhKey, eph), fromB64url(wrap.ephPub), ctx, "decrypt");
    const raw = await p.aesGcmDecrypt(kek, iv, wrapped, wrapAad(ctx));
    return await p.importAesKey(raw, ["encrypt", "decrypt"], true);
  } catch {
    throw invalid();
  }
};

const commitmentOf = async (roomKey, roomId, version) =>
  toB64url(await p.sha256(concat(canonical([COMMIT_LABEL, roomId, version]), await p.exportRaw(roomKey))));

const commitRoomKey = async ({ roomKey, roomId, version, creatorEcdsaKey }) => {
  const commitment = await commitmentOf(roomKey, roomId, version);
  const sig = await p.ecdsaSign(creatorEcdsaKey, canonical([COMMIT_SIG_LABEL, roomId, version, commitment]));
  return { commitment, commitmentSig: toB64url(sig) };
};

// Falha (KEY_COMMITMENT_MISMATCH) se a assinatura não for do criador ou se a
// chave não for a comprometida. Não distingue os dois casos.
const verifyRoomKeyCommitment = async ({ roomKey, roomId, version, commitment, commitmentSig, creatorEcdsaPub }) => {
  const mismatch = () => new E2eeError("KEY_COMMITMENT_MISMATCH", "a chave da sala não confere com o compromisso do criador");
  const verifyKey = await importVerifyKey(creatorEcdsaPub);
  let ok;
  try {
    const sig = fromB64url(commitmentSig);
    ok =
      sig.length === SIG_BYTES &&
      (await p.ecdsaVerify(verifyKey, sig, canonical([COMMIT_SIG_LABEL, roomId, version, commitment]))) &&
      (await commitmentOf(roomKey, roomId, version)) === commitment;
  } catch {
    ok = false;
  }
  if (!ok) throw mismatch();
};

module.exports = {
  generateRoomKey,
  wrapRoomKey,
  unwrapRoomKey,
  commitRoomKey,
  verifyRoomKeyCommitment,
  WRAP: { IV_BYTES, SIG_BYTES, WRAPPED_BYTES },
};
