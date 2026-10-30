// Formatos aceitos por cada rota. Campos não listados são descartados pelo
// zod (ex.: um "user" forjado no corpo de POST /messages nem chega à rota).
const { z } = require("zod");
const { isP256Spki, isB64urlBytes } = require("../helpers/publicKeys");
const { parseRoomNameEnvelope } = require("../helpers/roomName");
const { MIN_RETENTION_SECONDS, MAX_TTL_SECONDS } = require("../helpers/expiry");

const INT_MAX = 2147483647; // limite do tipo INTEGER do Postgres

// Em JSON, IDs devem ser números inteiros de verdade (não "1", nem 1.5).
const id = z.number().int().positive().max(INT_MAX);
// Em parâmetros de URL chegam como texto: só dígitos, sem sinal/expoente.
const idParam = z
  .string()
  .regex(/^[1-9][0-9]{0,9}$/)
  .transform(Number)
  .pipe(id);

// Normalizado (sem espaços, minúsculo) antes de validar: "Alice@X.com" e
// "alice@x.com" são a mesma conta, no cadastro, no login e no rate limit.
const email = z.string().trim().toLowerCase().pipe(z.email().max(254));

// O bcrypt ignora tudo depois do 72º BYTE: senhas maiores seriam truncadas
// em silêncio. O limite é em bytes (UTF-8), não em caracteres.
const MAX_PASSWORD_BYTES = 72;
const fitsBcrypt = (value) => Buffer.byteLength(value, "utf8") <= MAX_PASSWORD_BYTES;
const newPassword = z.string().min(10).refine(fitsBcrypt);
// No login, só o limite do bcrypt: a regra de tamanho mínimo é do cadastro.
const loginPassword = z.string().min(1).refine(fitsBcrypt);

// Chaves públicas da E2EE: SPKI P-256 em base64url canônico (conferido com
// o OpenSSL, não só pelo formato), e chaves distintas para ECDH e ECDSA.
const publicKey = z.string().refine(isP256Spki);
const publicKeys = z
  .object({ ecdhPub: publicKey, ecdsaPub: publicKey })
  .refine((keys) => keys.ecdhPub !== keys.ecdsaPub);

// Wrap da chave da sala (D4): só a ESTRUTURA é conferida (o servidor não
// tem como verificar a assinatura sem confiar na chave do remetente, e nunca
// abre o wrap). Tamanhos fixos: iv 12 B, wrapped 32 B + tag 16 B, sig 64 B.
const b64urlBytes = (bytes) => z.string().refine((v) => isB64urlBytes(v, bytes));
const wrap = z.object({ ephPub: publicKey, iv: b64urlBytes(12), wrapped: b64urlBytes(48), sig: b64urlBytes(64) });
const keyVersion = id;

const displayName = z.string().trim().min(1).max(100);
// Etapa 5 (A3): o nome da sala só chega cifrado (shared/e2ee/roomName.js).
const nameEnv = z.string().refine((value) => parseRoomNameEnvelope(value) !== null);
// Etapa 5 (A1): retenção de 1 min a 7 d, ou null (sem limite).
const retentionSeconds = z.number().int().min(MIN_RETENTION_SECONDS).max(MAX_TTL_SECONDS).nullable();

const schemas = {
  register: { body: z.object({ email, password: newPassword, name: displayName }) },
  login: { body: z.object({ email, password: loginPassword }) },
  // Sem nome em claro: um "name" no corpo é RECUSADO (strict), em vez de
  // descartado em silêncio — o cliente não pode achar que o gravou.
  createRoom: { body: z.object({}).strict() },
  joinRooms: { body: z.object({ idRoom: id, key: z.string().min(1).max(128) }) },
  // Histórico paginado: as `limit` mais recentes (padrão 50, máximo 100)
  // com id menor que `before`, para paginar para trás.
  getMessages: {
    params: z.object({ id: idParam }),
    query: z.object({
      limit: z.string().regex(/^[0-9]{1,3}$/).transform(Number).pipe(z.number().int().min(1).max(100)).default(50),
      before: idParam.optional(),
    }),
  },
  updateLastViewed: {
    body: z.object({ room: id, idLastMessage: z.number().int().nonnegative().max(INT_MAX) }),
  },
  roomUsers: { params: z.object({ room: idParam }) },
  putKeys: { body: publicKeys },
  publishRoomKey: {
    params: z.object({ id: idParam }),
    body: z.object({ version: keyVersion, wrap, commitment: b64urlBytes(32), commitmentSig: b64urlBytes(64), nameEnv }),
  },
  roomKeys: { params: z.object({ id: idParam }) },
  postWrap: {
    params: z.object({ id: idParam }),
    body: z.object({ version: keyVersion, recipientId: id, recipientKeyEpoch: id, wrap }),
  },
  getKeys: { params: z.object({ userId: idParam }) },
  // Ciclo de vida dos membros (Etapa 4b-2).
  leaveRoom: { params: z.object({ id: idParam }) },
  removeMember: { params: z.object({ id: idParam, userId: idParam }) },
  transferOwner: { params: z.object({ id: idParam }), body: z.object({ userId: id }) },
  // Rotação (D3): versão nova, compromisso do autor e um wrap por membro
  // atual (incluindo o autor). Até 200 wraps (limite de corpo de 100 KB).
  rotateRoomKey: {
    params: z.object({ id: idParam }),
    body: z.object({
      version: keyVersion,
      commitment: b64urlBytes(32),
      commitmentSig: b64urlBytes(64),
      wraps: z.array(z.object({ recipientId: id, recipientKeyEpoch: id, wrap })).min(1).max(200),
      nameEnv,
    }),
  },
  // Etapa 5: ajustes da sala, só pelo dono (routes/roomSettings.js).
  setRetention: { params: z.object({ id: idParam }), body: z.object({ retentionSeconds }) },
  setName: { params: z.object({ id: idParam }), body: z.object({ nameEnv }) },
  unban: { params: z.object({ id: idParam, userId: idParam }) },
};

module.exports = schemas;
