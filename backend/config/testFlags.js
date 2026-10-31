// Política única das flags SÓ DE TESTE (Etapa 6, acréscimo da Parte B).
//
// Estas variáveis existem apenas para as mutações dos scripts de verificação
// (verify-e2ee.sh e attack-matrix.sh); cada uma ENFRAQUECE uma defesa de
// propósito. Regras, a favor da segurança (falha fechada):
//   1. Uma flag só é HONRADA quando NODE_ENV === "test" (honored()). Em
//      produção ou em desenvolvimento ela é ignorada pelo código que a lê.
//   2. Subir com NODE_ENV === "production" e QUALQUER flag de teste definida
//      é PROIBIDO: assertSafe() lança e o backend não sobe (createApp). Um
//      valor errado também conta como "definida" — na dúvida, recusa.
const TEST_FLAGS = ["TEST_SKIP_ROOM_MEMBER", "E2EE_TEST_SKIP_ROTATION", "E2EE_TEST_CLOCK", "E2EE_TEST_SKIP_PURGE"];

const isSet = (v) => v !== undefined && v !== "";
const flagsSet = (env = process.env) => TEST_FLAGS.filter((name) => isSet(env[name]));

// A flag `name` tem efeito? Só em NODE_ENV=test e com o valor exato pedido.
const honored = (name, expectedValue, env = process.env) => env.NODE_ENV === "test" && env[name] === expectedValue;

// Chamado no boot (createApp): recusa produção com qualquer flag de teste.
const assertSafe = (env = process.env) => {
  if (env.NODE_ENV === "production") {
    const on = flagsSet(env);
    if (on.length > 0) {
      throw new Error(
        `NODE_ENV=production não pode subir com flag(s) de teste definida(s): ${on.join(", ")}. ` +
          "Essas flags só valem em NODE_ENV=test (backend/config/testFlags.js)."
      );
    }
  }
};

module.exports = { TEST_FLAGS, flagsSet, honored, assertSafe };
