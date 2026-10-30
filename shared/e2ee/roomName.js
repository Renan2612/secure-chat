// Nome da sala cifrado E assinado pelo dono (Etapa 5, A3; docs/05 §12.2).
// O servidor guarda só name_env:
//   {"v":2,"kv":<versão da chave>,"iv":b64url(12),"ct":b64url}
//   conteúdo  = JSON canônico {"name","seq","ownerId","sig"}, com o padding
//               das mensagens (blocos de 128 bytes, até 256)
//   sig       = ECDSA(dono) sobre ["secure-chat/v1/room-name", roomId, seq, ownerId, name]
//   AAD       = JSON canônico ["room-name", roomId, kv]
//   ct        = AES-256-GCM(chave da sala kv, iv, conteúdo preenchido, AAD)
// O AAD amarra o envelope à sala e à versão da chave; a assinatura amarra o
// nome ao dono e a um contador (seq) crescente por sala. Quem rotaciona a
// chave (qualquer membro) recifra o MESMO conteúdo assinado com a chave nova,
// sem re-assinar: um não-dono consegue mudar o envelope, mas não o nome que
// os outros aceitam. O cliente guarda o maior seq visto (rollback).
const p = require("./primitives");
const { utf8, fromUtf8, toB64url, fromB64url, canonical } = require("./encoding");
const { pad, unpad } = require("./messages");
const { importVerifyKey } = require("./identity");
const { E2eeError } = require("./errors");

const NAME_ENVELOPE_VERSION = 2;
const NAME_LABEL = "room-name";
const NAME_SIG_LABEL = "secure-chat/v1/room-name";
const NAME_KEYS = ["v", "kv", "iv", "ct"];
const PAYLOAD_KEYS = ["name", "seq", "ownerId", "sig"];
const IV_BYTES = 12;
const SIG_BYTES = 64;
const TAG_BYTES = 16;
const PAD_BLOCK = 128;
const MAX_PADDED_BYTES = 2 * PAD_BLOCK;
// O conteúdo assinado ({name, seq, ownerId, sig} ≈ 143 bytes além do nome)
// tem de caber em 256 bytes preenchidos (menos os 2 do prefixo): o envelope
// fica abaixo dos 512 bytes que o servidor aceita. Escapes do JSON (aspas,
// controle) também contam: conferido ao cifrar.
const MAX_ROOM_NAME_BYTES = 100;
const MAX_CONTENT_BYTES = MAX_PADDED_BYTES - 2;
const MAX_NAME_ENV_BYTES = 512;
const MAX_INT = 2147483647;

const isId = (n) => Number.isSafeInteger(n) && n >= 1 && n <= MAX_INT;
const nameAad = (roomId, kv) => canonical([NAME_LABEL, roomId, kv]);
const signedData = ({ roomId, seq, ownerId, name }) => canonical([NAME_SIG_LABEL, roomId, seq, ownerId, name]);
const invalidName = (msg = "nome da sala malformado") => new E2eeError("INVALID_NAME", msg);

// Só o dono assina (PUT /rooms/:id/name, criação, re-assinatura ao assumir).
const signRoomName = async ({ roomId, seq, ownerId, name, ownerEcdsaKey }) => {
  if (typeof name !== "string" || name.length === 0) throw new E2eeError("EMPTY_TEXT", "nome da sala vazio");
  if (utf8(name).length > MAX_ROOM_NAME_BYTES) throw new E2eeError("TEXT_TOO_LONG", `nome da sala acima de ${MAX_ROOM_NAME_BYTES} bytes`);
  if (!isId(seq) || !isId(ownerId)) throw invalidName("seq e ownerId devem ser inteiros de 1 a 2^31 - 1");
  const sig = await p.ecdsaSign(ownerEcdsaKey, signedData({ roomId, seq, ownerId, name }));
  return { name, seq, ownerId, sig: toB64url(sig) };
};

// Qualquer membro com a chave cifra um conteúdo JÁ assinado (o da criação,
// o de uma troca de nome ou o recebido, numa rotação).
const encryptRoomName = async ({ roomKey, roomId, kv, payload }) => {
  const content = JSON.stringify({ name: payload.name, seq: payload.seq, ownerId: payload.ownerId, sig: payload.sig });
  if (utf8(content).length > MAX_CONTENT_BYTES) throw new E2eeError("TEXT_TOO_LONG", "nome da sala longo demais");
  const iv = p.randomBytes(IV_BYTES);
  const ct = await p.aesGcmEncrypt(roomKey, iv, pad(content), nameAad(roomId, kv));
  return JSON.stringify({ v: NAME_ENVELOPE_VERSION, kv, iv: toB64url(iv), ct: toB64url(ct) });
};

// Mesma regra estrutural do servidor (backend/helpers/roomName.js).
const parseEnvelope = (nameEnv) => {
  if (typeof nameEnv !== "string" || utf8(nameEnv).length > MAX_NAME_ENV_BYTES) throw invalidName();
  let env;
  try {
    env = JSON.parse(nameEnv);
  } catch {
    throw invalidName();
  }
  if (!env || typeof env !== "object" || Array.isArray(env) || Object.keys(env).join() !== NAME_KEYS.join()) throw invalidName();
  if (env.v !== NAME_ENVELOPE_VERSION || !isId(env.kv)) throw invalidName();
  let iv;
  let ct;
  try {
    iv = fromB64url(env.iv);
    ct = fromB64url(env.ct);
  } catch {
    throw invalidName();
  }
  const padded = ct.length - TAG_BYTES;
  if (iv.length !== IV_BYTES || padded < PAD_BLOCK || padded % PAD_BLOCK !== 0 || padded > MAX_PADDED_BYTES) throw invalidName();
  if (JSON.stringify(env) !== nameEnv) throw invalidName();
  return { kv: env.kv, iv, ct };
};

// Conteúdo decifrado, conferido só na ESTRUTURA (forma canônica, tipos).
const parsePayload = (text) => {
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    throw invalidName();
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || Object.keys(payload).join() !== PAYLOAD_KEYS.join()) throw invalidName();
  if (typeof payload.name !== "string" || payload.name.length === 0 || !isId(payload.seq) || !isId(payload.ownerId)) throw invalidName();
  if (typeof payload.sig !== "string" || JSON.stringify(payload) !== text) throw invalidName();
  return payload;
};

// Decifra (AAD da sala e da versão) e devolve o conteúdo SEM verificar a
// assinatura: quem decide o que mostrar é o openRoomName.
const decryptRoomName = async ({ nameEnv, roomKeys, roomId }) => {
  const env = parseEnvelope(nameEnv);
  const roomKey = roomKeys[env.kv];
  if (!roomKey) throw new E2eeError("MISSING_KEY", `sem a chave da versão ${env.kv}`);
  let text;
  try {
    text = unpad(await p.aesGcmDecrypt(roomKey, env.iv, env.ct, nameAad(roomId, env.kv)));
  } catch {
    throw invalidName("nome da sala não confere");
  }
  return parsePayload(text);
};

const verifyRoomName = async ({ payload, roomId, ownerEcdsaPub }) => {
  try {
    const sig = fromB64url(payload.sig);
    if (sig.length !== SIG_BYTES) return false;
    return await p.ecdsaVerify(await importVerifyKey(ownerEcdsaPub), sig, signedData({ roomId, ...payload }));
  } catch {
    return false;
  }
};

// Próximo seq que o dono assina: acima do último verificado (lastSeq) e do
// visto agora no servidor (seenSeq, mesmo não verificado: pode ser de um
// dono anterior que este cliente não viu). Pular números é inofensivo (os
// outros clientes comparam com o último verificado DELES). Achados da
// revisão: um não-dono que rotaciona escolhe o seq do conteúdo que publica
// (assinado por ele); sem limite, empurraria o contador do dono até o teto
// e ele nunca mais renomearia. Por isso o visto só conta até
// SEQ_WINDOW acima do último verificado; fora disso, é ignorado.
const SEQ_WINDOW = 1000;
const nextRoomNameSeq = (lastSeq, seenSeq) => {
  const last = lastSeq ?? 0;
  const seen = seenSeq ?? 0;
  const base = seen > last && seen - last <= SEQ_WINDOW ? seen : last;
  if (base + 1 > MAX_INT) throw invalidName("o contador do nome da sala chegou ao limite");
  return base + 1;
};

// O que mostrar como nome da sala. Entradas: o name_env do servidor (ou
// null), as chaves da sala, o dono ATUAL informado pelo servidor e a chave
// ECDSA FIXADA dele (trust store; undefined se não confiável) e `last`, o
// último conteúdo verificado guardado no keystore. Devolve:
//   name      nome a exibir, ou null ("Sala #id", "nome não verificado")
//   verified  o nome exibido foi assinado pelo dono atual
//   tampered  havia um nome verificado deste dono e o servidor trouxe outro
//             que não confere (assinatura, dono, seq menor, mesmo seq com
//             outro nome): "nome alterado por quem não é o dono"
//   remember  conteúdo novo, verificado e com seq maior: guardar
//   payload   conteúdo assinado por trás do nome exibido (para recifrar
//             numa rotação), ou null
//   seenSeq   seq do conteúdo decifrado, mesmo rejeitado (o dono assina o
//             próximo acima dele)
const openRoomName = async ({ nameEnv, roomKeys, roomId, ownerId, ownerEcdsaPub, last = null }) => {
  const keep = ownerEcdsaPub && last && last.ownerId === ownerId ? last : null;
  const kept = (tampered, seenSeq = null) => ({ name: keep?.name ?? null, verified: Boolean(keep), tampered: tampered && Boolean(keep), remember: null, payload: keep, seenSeq });
  if (nameEnv === null || nameEnv === undefined) return kept(false);
  let payload;
  try {
    payload = await decryptRoomName({ nameEnv, roomKeys, roomId });
  } catch (err) {
    return kept(err.code !== "MISSING_KEY");
  }
  if (!ownerEcdsaPub) return { ...kept(false, payload.seq), name: null, verified: false, payload: null };
  const signedByOwner = payload.ownerId === ownerId && (await verifyRoomName({ payload, roomId, ownerEcdsaPub }));
  if (!signedByOwner) return kept(true, payload.seq);
  if (last && (payload.seq < last.seq || (payload.seq === last.seq && (payload.name !== last.name || payload.ownerId !== last.ownerId)))) {
    return kept(true, payload.seq);
  }
  const fresh = !last || payload.seq > last.seq;
  return { name: payload.name, verified: true, tampered: false, remember: fresh ? payload : null, payload, seenSeq: payload.seq };
};

module.exports = {
  signRoomName,
  encryptRoomName,
  decryptRoomName,
  verifyRoomName,
  openRoomName,
  nextRoomNameSeq,
  parseRoomNameEnvelope: (nameEnv) => ({ kv: parseEnvelope(nameEnv).kv }),
  MAX_ROOM_NAME_BYTES,
  MAX_NAME_ENV_BYTES,
};
