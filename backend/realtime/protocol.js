// Protocolo de tempo real do secure-chat — versão 1 (docs/03-protocolo.md).
//
// Quadros de TEXTO UTF-8 com um envelope JSON { v, type, id?, ...payload }.
// Os pacotes do cliente são validados com zod; campos não previstos são
// descartados (ex.: um "from" forjado nunca chega aos handlers).
const { z } = require("zod");

const PROTOCOL_VERSION = 1;
const PROTOCOL_PATH = "/ws";

const DEFAULT_LIMITS = {
  maxConnectionsPerUser: 5,
  maxConnections: 1000,
  helloTimeoutMs: 5000,
  maxPayloadBytes: 16 * 1024,
  maxBodyBytes: 8 * 1024,
};

// Códigos de fechamento (RFC 6455 §7.4; 4000–4999 = uso privado da aplicação).
const CLOSE = {
  POLICY_VIOLATION: 1008,
  MESSAGE_TOO_BIG: 1009,
  SESSION_ENDED: 4401,
  HELLO_TIMEOUT: 4408,
  UNSUPPORTED_VERSION: 4426,
  RATE_LIMITED: 4429,
};

// Códigos do pacote ERROR.
const ERRORS = {
  BAD_REQUEST: "Pacote inválido",
  HELLO_REQUIRED: "Envie HELLO antes de qualquer outro pacote",
  UNSUPPORTED_VERSION: `Versão de protocolo não suportada (servidor: ${PROTOCOL_VERSION})`,
  NOT_MEMBER: "Sem acesso a esta sala",
  CID_REUSED: "cid já usado em outra sala",
  INTERNAL: "Erro interno",
};

const INT_MAX = 2147483647;

// "id" opcional: identificador da requisição escolhido pelo cliente,
// devolvido como "ref" nas respostas e erros correspondentes.
const base = { v: z.literal(PROTOCOL_VERSION), id: z.string().min(1).max(64).optional() };

const room = z.number().int().positive().max(INT_MAX);

const clientPacket = z.discriminatedUnion("type", [
  z.object({ ...base, type: z.literal("HELLO"), client: z.string().max(64).optional() }),
  z.object({ ...base, type: z.literal("PING") }),
  z.object({ ...base, type: z.literal("SUBSCRIBE"), room }),
  z.object({ ...base, type: z.literal("UNSUBSCRIBE"), room }),
  // Sem "from": o remetente é sempre o usuário da sessão (item C).
  z.object({ ...base, type: z.literal("MSG_SEND"), room, cid: z.string(), body: z.string() }),
]);

module.exports = {
  PROTOCOL_VERSION,
  PROTOCOL_PATH,
  DEFAULT_LIMITS,
  CLOSE,
  ERRORS,
  INT_MAX,
  clientPacket,
};
