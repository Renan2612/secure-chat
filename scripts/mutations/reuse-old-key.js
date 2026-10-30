// MUTAÇÃO para validar o scripts/verify-e2ee.sh (MUTATION=reuse-old-key): ao
// trocar a chave da sala, o cliente reaproveita a chave ATUAL em vez de gerar
// uma nova aleatória (como um "ratchet" ingênuo ou um bug). Vale para
// qualquer cliente que rotacione (a rotação automática pode ser de qualquer
// membro). Carregada com `node --require`, antes do ws-client; o código de
// produção não muda. Esperado: o removido ainda tem essa chave e decifra o
// que vem depois (ou o outro membro recusa a versão, KEY_REUSED, e a
// mensagem nova nem é enviada) → o verify-e2ee.sh sai com código != 0.
const path = require("path");
const e2ee = require(path.join(__dirname, "..", "..", "shared", "e2ee"));
const { E2eeSession } = require(path.join(__dirname, "..", "..", "backend", "tools", "e2ee-session"));

const realRotate = E2eeSession.prototype.rotate;
E2eeSession.prototype.rotate = async function rotate(room, options) {
  await this.ensureRoomKey(room);
  const old = (await this.roomKeysFor(room))[this.currentVersion.get(room)];
  const realGenerate = e2ee.generateRoomKey;
  e2ee.generateRoomKey = async () => old ?? realGenerate();
  try {
    return await realRotate.call(this, room, options);
  } finally {
    e2ee.generateRoomKey = realGenerate;
  }
};
