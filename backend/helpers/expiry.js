// Expiração das mensagens (Etapa 5, A1; docs/05-e2ee.md). O exp vem
// ASSINADO no envelope v2 (o servidor não consegue alterá-lo sem quebrar a
// verificação); aqui só se conferem os limites, com o relógio do servidor:
//   exp null      → sem expiração (proibido se a sala tem retenção)
//   exp inteiro   → agora + 30 s − 5 min <= exp <= agora + 7 d + 5 min, e
//                   nunca já vencido; com retenção R, exp <= agora + R + 5 min
// Os 5 min são a tolerância para o relógio do cliente. Mesmas constantes de
// shared/e2ee/messages.js (o shared/ não entra na imagem do backend).
const MIN_TTL_SECONDS = 30;
const MAX_TTL_SECONDS = 7 * 24 * 3600;
const CLOCK_SKEW_SECONDS = 5 * 60;
const MIN_RETENTION_SECONDS = 60;

// Relógio do servidor. Injetável (createServer/createApp/attachRealtime
// recebem `clock`) só para os testes; em produção é sempre este.
const systemClock = Object.freeze({ nowMs: () => Date.now() });

const nowSeconds = (clock) => Math.floor(clock.nowMs() / 1000);

// null se o exp é aceitável fora da questão da retenção da sala (que é
// conferida no INSERT, junto com a linha da sala); senão o código do ERROR.
const expProblem = (exp, nowSec) => {
  if (exp === null) return null;
  if (exp <= nowSec || exp < nowSec + MIN_TTL_SECONDS - CLOCK_SKEW_SECONDS) return "TTL_INVALID";
  if (exp > nowSec + MAX_TTL_SECONDS + CLOCK_SKEW_SECONDS) return "TTL_INVALID";
  return null;
};

module.exports = {
  MIN_TTL_SECONDS,
  MAX_TTL_SECONDS,
  CLOCK_SKEW_SECONDS,
  MIN_RETENTION_SECONDS,
  systemClock,
  nowSeconds,
  expProblem,
};
