// Protocolo de tempo real do secure-chat — versão 1 (docs/03-protocolo.md).
//
// Quadros de TEXTO UTF-8 com um envelope JSON { v, type, id?, ...payload }.
// Os pacotes do cliente são validados com zod; campos não previstos são
// descartados (ex.: um "from" forjado nunca chega aos handlers).
const { z } = require("zod");

const PROTOCOL_VERSION = 1;
const PROTOCOL_PATH = "/ws";

// Tamanho máximo do body em BYTES UTF-8 — o mesmo do CHECK da coluna
// messages.message (database/migrations.sql). Não é configurável por
// instância porque o banco é compartilhado.
const MAX_BODY_BYTES = 8192;

const DEFAULT_LIMITS = {
  maxConnectionsPerUser: 5,
  maxConnections: 1000,
  helloTimeoutMs: 5000,
  maxPayloadBytes: 16 * 1024,
  maxBodyBytes: MAX_BODY_BYTES,
  maxInvalidPackets: 3, // no 3º pacote malformado/fora do schema: close 1008
  // Token bucket por conexão: cada quadro gasta uma ficha.
  rateBurst: 20, // capacidade do balde (rajada máxima)
  rateRefillPerSec: 10, // fichas repostas por segundo (ritmo sustentado)
  maxRateViolations: 20, // quadros descartados seguidos até o close 4429
  // Após um 4429, o usuário não reabre conexão por este tempo (senão
  // reconectar daria um balde novo e cheio).
  rateLimitCooldownMs: 60 * 1000,
  // A cada ciclo: ping de controle (RFC 6455) a todas as conexões; quem não
  // respondeu ao ping anterior é derrubado. A sessão de cada conexão também
  // é conferida no store (expirou ou foi apagada → close 4401).
  heartbeatIntervalMs: 30 * 1000,
  // Backpressure: dados aguardando envio a um cliente que não lê. Acima
  // disso, a conexão é encerrada (cliente lento não acumula memória aqui).
  maxBufferedBytes: 1024 * 1024,
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
  RATE_LIMITED: "Pacotes demais; aguarde",
  NOT_MEMBER: "Sem acesso a esta sala",
  CID_REUSED: "cid já usado em outra sala",
  INTERNAL: "Erro interno",
};

const INT_MAX = 2147483647;

// "id" opcional: identificador da requisição escolhido pelo cliente,
// devolvido como "ref" nas respostas e erros correspondentes.
const base = { v: z.literal(PROTOCOL_VERSION), id: z.string().min(1).max(64).optional() };

const room = z.number().int().positive().max(INT_MAX);

// Body OPACO: o servidor só confere tipo e tamanho (não apara, não
// interpreta). O NUL é recusado porque o Postgres não o aceita em TEXT.
const body = z
  .string()
  .min(1)
  .refine((value) => Buffer.byteLength(value, "utf8") <= MAX_BODY_BYTES && !value.includes("\u0000"));

// Gerado pelo cliente (ex.: UUID); charset restrito, ecoado no MSG_ACK.
const cid = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);

const clientPacket = z.discriminatedUnion("type", [
  z.object({ ...base, type: z.literal("HELLO"), client: z.string().max(64).optional() }),
  z.object({ ...base, type: z.literal("PING") }),
  z.object({ ...base, type: z.literal("SUBSCRIBE"), room }),
  z.object({ ...base, type: z.literal("UNSUBSCRIBE"), room }),
  // Sem "from": o remetente é sempre o usuário da sessão (item C).
  z.object({ ...base, type: z.literal("MSG_SEND"), room, cid, body }),
]);

module.exports = {
  PROTOCOL_VERSION,
  PROTOCOL_PATH,
  DEFAULT_LIMITS,
  MAX_BODY_BYTES,
  CLOSE,
  ERRORS,
  clientPacket,
};
