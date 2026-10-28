// Ambiente dos processos do ws-client nos testes (Etapa 4b): HOME e keystore
// em diretório temporário (nunca o ~/.config real nem o repositório) e uma
// senha de cifragem DIFERENTE da senha de login.
const fs = require("fs");
const os = require("os");
const path = require("path");

const KEY_PASSPHRASE = "senha-de-cifragem-dos-testes";

const clientHome = () => fs.mkdtempSync(path.join(os.tmpdir(), "ws-client-home-"));

// Argumentos e variáveis para um cliente com keystore próprio em `home`.
const clientSetup = (home = clientHome(), name = "keystore.json") => ({
  home,
  keystore: path.join(home, name),
  args: ["--keystore", path.join(home, name)],
  env: { HOME: home, CHAT_KEY_PASSPHRASE: KEY_PASSPHRASE },
});

module.exports = { KEY_PASSPHRASE, clientHome, clientSetup };
