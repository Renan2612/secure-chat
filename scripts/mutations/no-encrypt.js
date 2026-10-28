// MUTAÇÃO para validar o scripts/verify-e2ee.sh (MUTATION=no-encrypt): o
// cliente "esquece" de cifrar e manda o texto puro como body. Carregada com
// `node --require`, antes do ws-client; o código de produção não muda.
// Esperado: o servidor recusa (E2EE_REQUIRED), ninguém recebe a mensagem e
// o verify-e2ee.sh sai com código != 0.
const path = require("path");
const e2ee = require(path.join(__dirname, "..", "..", "shared", "e2ee"));

e2ee.encryptMessage = async ({ text }) => text;
