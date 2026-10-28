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
  const app = createApp({ ...appOptions, session, onSessionEnd });
  const server = http.createServer(app);
  realtime = attachRealtime(server, { session, ...realtimeOptions });
  return { app, server, realtime };
};

module.exports = { createServer };
