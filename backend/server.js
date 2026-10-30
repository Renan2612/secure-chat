// Carregado primeiro: qualquer módulo abaixo que leia process.env precisa
// encontrar as variáveis já disponíveis.
require("dotenv").config();

const { createServer } = require("./createServer");
const pool = require("./db");
const { systemClock } = require("./helpers/expiry");
const { createPurger, purgeIntervalFromEnv } = require("./helpers/purge");
const { testHooksFromEnv, createTestClock } = require("./helpers/testHooks");

// Ganchos de teste do verify-e2ee.sh: desligados por padrão (helpers/testHooks.js).
const { testClock, skipPurge } = testHooksFromEnv();
const clock = testClock ? createTestClock() : systemClock;

// O Socket.IO foi REMOVIDO na Etapa 3: aceitava conexões sem autenticação e
// fazia broadcast global de todas as salas. O tempo real agora é um
// protocolo próprio sobre WebSocket em /ws (realtime/, docs/03-protocolo.md).
const { server } = createServer({ clock });

const purger = createPurger({ pool, clock, intervalMs: purgeIntervalFromEnv(), skip: skipPurge });
purger.start();

const PORT = process.env.SERVER_PORT || 8000;
if (process.env.E2EE_TEST_SKIP_ROTATION) {
  console.error("[PERIGO] E2EE_TEST_SKIP_ROTATION definido: com o valor de teste, o servidor NÃO exige a troca da chave depois de uma saída (só para a mutação do verify-e2ee.sh)");
}
if (testClock) {
  console.error("[PERIGO] E2EE_TEST_CLOCK definido: SIGUSR2 adianta o relógio da expiração em 1 h e expurga (só para o verify-e2ee.sh)");
  process.on("SIGUSR2", () => {
    clock.advance();
    purger.purgeNow().catch((err) => console.error(`[purge] falha no expurgo: code=${err.code ?? "-"} ${err.message}`));
  });
}
if (skipPurge) {
  console.error("[PERIGO] E2EE_TEST_SKIP_PURGE definido: as mensagens expiradas NÃO são apagadas do banco (só para a mutação do verify-e2ee.sh)");
}
server.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
