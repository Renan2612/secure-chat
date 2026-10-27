// Formatos aceitos por cada rota. Campos não listados são descartados pelo
// zod (ex.: um "user" forjado no corpo de POST /messages nem chega à rota).
const { z } = require("zod");

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

const displayName = z.string().trim().min(1).max(100);
const roomName = z.string().trim().min(1).max(100);

const schemas = {
  register: { body: z.object({ email, password: newPassword, name: displayName }) },
  login: { body: z.object({ email, password: loginPassword }) },
  createRoom: { body: z.object({ name: roomName }) },
  checkRoomExists: { body: z.object({ name: roomName }) },
  joinRooms: { body: z.object({ idRoom: id, key: z.string().min(1).max(128) }) },
  getMessages: { params: z.object({ id: idParam }) },
  postMessage: { body: z.object({ room: id, message: z.string().trim().min(1).max(500) }) },
  updateLastViewed: {
    body: z.object({ room: id, idLastMessage: z.number().int().nonnegative().max(INT_MAX) }),
  },
  roomUsers: { params: z.object({ room: idParam }) },
};

module.exports = schemas;
