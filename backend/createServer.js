// Monta o servidor completo: app HTTP (Express) + canal em tempo real (/ws),
// compartilhando a mesma sessão (store no Postgres).
const http = require("http");
const { createApp } = require("./app");
const { createSession } = require("./config/session");
const { attachRealtime } = require("./realtime");

const createServer = ({ appOptions = {}, realtimeOptions = {} } = {}) => {
  const session = createSession();
  const app = createApp({ ...appOptions, session });
  const server = http.createServer(app);
  const realtime = attachRealtime(server, { session, ...realtimeOptions });
  return { app, server, realtime };
};

module.exports = { createServer };
