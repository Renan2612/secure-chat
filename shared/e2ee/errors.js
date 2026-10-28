// Erro único da E2EE. `code` diz o que falhou sem detalhar o porquê
// criptográfico (não ajudar um atacante a calibrar adulterações):
//   INVALID_ENVELOPE  body não é um envelope v1 bem formado
//   INVALID_MESSAGE   assinatura, AAD ou texto cifrado não conferem
//   INVALID_WRAP      wrap da chave da sala não confere
//   INVALID_KEY       chave pública malformada ou de outro tipo/curva
//   MISSING_KEY       não temos a chave da versão pedida
//   TEXT_TOO_LONG / EMPTY_TEXT  limites do texto claro
//   BAD_PASSPHRASE    keystore: senha de cifragem errada ou arquivo adulterado
class E2eeError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "E2eeError";
    this.code = code;
  }
}

module.exports = { E2eeError };
