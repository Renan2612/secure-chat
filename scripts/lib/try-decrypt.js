#!/usr/bin/env node
// Uso: TRY_KEYPASS=... node scripts/lib/try-decrypt.js KEYSTORE < candidatos.jsonl
// Abre o keystore de um usuário (senha de cifragem só por variável de
// ambiente) e tenta, com TUDO o que ele guarda (identidade e todas as chaves
// de sala de todas as versões), abrir cada candidato, um JSON por linha:
//   {"kind":"message","room":7,"from":3,"cid":"…","body":"{envelope}","senderEcdsaPub":"…"}
//   {"kind":"wrap","room":7,"version":2,"recipientId":5,"senderId":3,"ephPub":"…","iv":"…","wrapped":"…","sig":"…","senderEcdsaPub":"…"}
// Para cada linha imprime "ok <texto>" (mensagem), "ok wrap" ou "fail <código>".
// Uma mensagem é tentada com a chave da versão dela E com cada uma das
// outras (um removido que "chuta" a chave antiga no lugar da nova). Um wrap
// é tentado como se fosse para o próprio usuário e para o destinatário real.
// Só um erro de criptografia (E2eeError) conta como "não abre"; qualquer
// outro (bug, parâmetro errado) aborta com 2, para nunca virar um OK falso.
// Sai 0 se rodou até o fim (o chamador interpreta as linhas); 2 em erro.
process.on("uncaughtException", (err) => {
  process.stderr.write(`try-decrypt: ${err.message}\n`);
  process.exit(2);
});
const fs = require("fs");
const path = require("path");
const files = require(path.join(__dirname, "..", "..", "shared", "e2ee", "node"));
const e2ee = require(path.join(__dirname, "..", "..", "shared", "e2ee"));

const keystore = process.argv[2];
if (!keystore || !process.env.TRY_KEYPASS) {
  process.stderr.write("uso: TRY_KEYPASS=... try-decrypt.js KEYSTORE < candidatos\n");
  process.exit(2);
}

const main = async () => {
  const data = await files.readSealedFile(keystore, process.env.TRY_KEYPASS);
  const identity = await e2ee.importIdentity(data.identity);
  const keysOf = async (room) => {
    const out = [];
    for (const raw of Object.values(data.roomKeys?.[room] ?? {})) {
      out.push(await e2ee.primitives.importAesKey(e2ee.encoding.fromB64url(raw), ["encrypt", "decrypt"], true));
    }
    return out;
  };
  const lines = fs.readFileSync(0, "utf8").split("\n").filter(Boolean);
  for (const line of lines) {
    const c = JSON.parse(line);
    if (c.kind === "message") {
      const env = e2ee.parseEnvelope(c.body);
      let text = null;
      for (const key of await keysOf(c.room)) {
        try {
          text = await e2ee.decryptMessage({ body: c.body, roomKeys: { [env.kv]: key }, roomId: c.room, senderId: c.from, cid: c.cid, senderEcdsaPub: c.senderEcdsaPub });
          break;
        } catch (err) {
          if (!(err instanceof e2ee.E2eeError)) throw err; // bug do detector ≠ "não abre"
        }
      }
      process.stdout.write(text === null ? "fail NO_KEY_OPENS\n" : `ok ${text}\n`);
    } else if (c.kind === "wrap") {
      let opened = false;
      for (const recipientId of new Set([data.userId, c.recipientId])) {
        try {
          await e2ee.unwrapRoomKey({ wrap: c, roomId: c.room, version: c.version, senderId: c.senderId, recipientId, recipientEcdhKey: identity.ecdh.privateKey, senderEcdsaPub: c.senderEcdsaPub });
          opened = true;
        } catch (err) {
          if (!(err instanceof e2ee.E2eeError)) throw err;
        }
      }
      process.stdout.write(opened ? "ok wrap\n" : "fail INVALID_WRAP\n");
    } else {
      throw new Error(`candidato desconhecido: ${c.kind}`);
    }
  }
};
main().catch((err) => {
  process.stderr.write(`try-decrypt: ${err.message}\n`);
  process.exit(2);
});
