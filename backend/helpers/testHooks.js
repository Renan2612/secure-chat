// Ganchos SÓ PARA O scripts/verify-e2ee.sh (Etapa 5). Ligados apenas com o
// valor exato abaixo — "1", "true" ou qualquer outro não liga — e nunca por
// padrão; o backend avisa no log ao subir (server.js).
//   E2EE_TEST_CLOCK: relógio de teste. Cada SIGUSR2 adianta o relógio da
//     expiração em 1 h e roda o expurgo na hora: o script prova que a
//     efêmera some sem esperar o tempo real.
//   E2EE_TEST_SKIP_PURGE: o expurgo não apaga nada (mutação "servidor sem
//     expurgo": o script precisa perceber e sair com 1).
const TEST_VALUE = "inseguro-so-para-teste";
const TEST_CLOCK_STEP_MS = 60 * 60 * 1000;

const testHooksFromEnv = (env = process.env) => ({
  testClock: env.E2EE_TEST_CLOCK === TEST_VALUE,
  skipPurge: env.E2EE_TEST_SKIP_PURGE === TEST_VALUE,
});

// Relógio que só anda para a frente quando advance() é chamado.
const createTestClock = (base = () => Date.now()) => {
  let offsetMs = 0;
  return {
    nowMs: () => base() + offsetMs,
    advance: (ms = TEST_CLOCK_STEP_MS) => {
      offsetMs += ms;
    },
  };
};

module.exports = { TEST_VALUE, TEST_CLOCK_STEP_MS, testHooksFromEnv, createTestClock };
