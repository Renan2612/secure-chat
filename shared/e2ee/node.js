// Adaptador Node da E2EE: o que o núcleo isomórfico não pode fazer no
// navegador — arquivos do keystore e do trust store, com permissões.
//
// Regras (D2): arquivo 0600 em diretório 0700; recusa abrir arquivo com
// permissão para grupo/outros, de outro dono ou que seja link simbólico (como
// o ssh faz com as chaves); NUNCA dentro de um repositório git (nem deste,
// nem de outro): um `git add .` descuidado publicaria as chaves privadas.
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

// Node ≥ 19 já expõe o Web Crypto em globalThis.crypto; garante para o núcleo.
if (!globalThis.crypto?.subtle) globalThis.crypto = crypto.webcrypto;

const { sealJson, openJson } = require("./keystore");

const EMAIL_FILE_NAME = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$/;

const defaultKeystorePath = (email, home = os.homedir()) => {
  if (typeof email !== "string" || !EMAIL_FILE_NAME.test(email) || email.startsWith(".")) {
    throw new Error("e-mail inválido para nome de arquivo do keystore");
  }
  return path.join(home, ".config", "secure-chat", `${email.toLowerCase()}.json`);
};

const trustStorePath = (keystorePath) =>
  keystorePath.endsWith(".json") ? `${keystorePath.slice(0, -".json".length)}.trust.json` : `${keystorePath}.trust.json`;

// Sobe a partir do diretório do arquivo (resolvendo links nos ancestrais que
// já existem) procurando um .git.
const insideGitRepo = (file) => {
  let dir = path.dirname(path.resolve(file));
  while (!fs.existsSync(dir)) dir = path.dirname(dir);
  dir = fs.realpathSync(dir);
  for (;;) {
    if (fs.existsSync(path.join(dir, ".git"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
};

const refuseRepo = (file) => {
  const repo = insideGitRepo(file);
  if (repo) throw new Error(`recusado: ${file} fica dentro de um repositório git (${repo}); use um caminho fora dele`);
};

// Grava de forma atômica: arquivo temporário 0600 criado do zero (wx) e
// rename por cima — nunca deixa um keystore pela metade.
const writeSealedFile = async (file, passphrase, data) => {
  refuseRepo(file);
  const sealed = await sealJson(passphrase, data);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.tmp-${crypto.randomUUID()}`;
  try {
    fs.writeFileSync(tmp, `${JSON.stringify(sealed)}\n`, { mode: 0o600, flag: "wx" });
    fs.chmodSync(tmp, 0o600); // independe do umask
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
};

const readSealedFile = async (file, passphrase) => {
  refuseRepo(file);
  const st = fs.lstatSync(file);
  if (st.isSymbolicLink()) throw new Error(`recusado: ${file} é um link simbólico`);
  if (!st.isFile()) throw new Error(`recusado: ${file} não é um arquivo comum`);
  if ((st.mode & 0o077) !== 0) {
    throw new Error(`recusado: permissões abertas demais em ${file} (${(st.mode & 0o777).toString(8)}); use chmod 600`);
  }
  if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
    throw new Error(`recusado: ${file} pertence a outro usuário`);
  }
  return openJson(passphrase, JSON.parse(fs.readFileSync(file, "utf8")));
};

module.exports = { defaultKeystorePath, trustStorePath, writeSealedFile, readSealedFile, insideGitRepo };
