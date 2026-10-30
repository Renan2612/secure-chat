// Monta o servidor completo: app HTTP (Express) + canal em tempo real (/ws),
// compartilhando a mesma sessão (store no Postgres).
const http = require("http");
const { createApp } = require("./app");
const { createSession } = require("./config/session");
const { attachRealtime } = require("./realtime");
const { systemClock } = require("./helpers/expiry");

// clock: relógio da expiração das mensagens (app e realtime usam o mesmo);
// só os testes injetam outro.
const createServer = ({ appOptions = {}, realtimeOptions = {}, clock = systemClock } = {}) => {
  const session = createSession();
  // O app nasce antes do realtime; o logout chama o realtime já montado.
  let realtime;
  const onSessionEnd = (userId) => realtime.closeUser(userId);
  const notify = {
    keyPending: (room) => realtime.notify.keyPending(room),
    keyReady: (userId, room) => realtime.notify.keyReady(userId, room),
    removed: (userId, room) => realtime.notify.removed(userId, room),
    rotationPending: (room) => realtime.notify.rotationPending(room),
    keyRotated: (room) => realtime.notify.keyRotated(room),
    retentionChanged: (room, seconds) => realtime.notify.retentionChanged(room, seconds),
    renamed: (room) => realtime.notify.renamed(room),
    ownerChanged: (room, ownerId) => realtime.notify.ownerChanged(room, ownerId),
  };
  const app = createApp({ ...appOptions, session, onSessionEnd, notify, clock });
  const server = http.createServer(app);
  // Mesma regra de confiança no X-Forwarded-For das rotas HTTP (TRUST_PROXY).
  realtime = attachRealtime(server, { session, trustProxy: app.get("trust proxy fn"), clock, ...realtimeOptions });
  return { app, server, realtime };
};

module.exports = { createServer };
