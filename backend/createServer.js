// Monta o servidor completo: app HTTP (Express) + canal em tempo real (/ws),
// compartilhando a mesma sessão (store no Postgres).
const http = require("http");
const { createApp } = require("./app");
const { createSession } = require("./config/session");
const { attachRealtime } = require("./realtime");

const createServer = ({ appOptions = {}, realtimeOptions = {} } = {}) => {
  const session = createSession();
  // O app nasce antes do realtime; o logout chama o realtime já montado.
  let realtime;
  const onSessionEnd = (userId) => realtime.closeUser(userId);
  const notify = {
    keyPending: (room) => realtime.notify.keyPending(room),
    keyReady: (userId, room) => realtime.notify.keyReady(userId, room),
  };
  const app = createApp({ ...appOptions, session, onSessionEnd, notify });
  const server = http.createServer(app);
  // Mesma regra de confiança no X-Forwarded-For das rotas HTTP (TRUST_PROXY).
  realtime = attachRealtime(server, { session, trustProxy: app.get("trust proxy fn"), ...realtimeOptions });
  return { app, server, realtime };
};

module.exports = { createServer };
