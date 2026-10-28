// Canal em tempo real: protocolo próprio sobre WebSocket (RFC 6455) no
// caminho /ws do mesmo servidor HTTP. Substitui o Socket.IO, que aceitava
// qualquer conexão e fazia broadcast global (itens A e B do baseline).
//
// O upgrade HTTP → WebSocket só é aceito depois de, nesta ordem:
//   1. caminho == /ws                          (senão 404)
//   2. Origin == CLIENT_URL                    (senão 403 — Cross-Site WebSocket Hijacking)
//   3. cookie "sid" com sessão válida no store (senão 401 — mesma sessão da API)
//   4. limites de conexões (por usuário: 429; total: 503)
// Recusas respondem HTTP com corpo JSON genérico e fecham o TCP: o socket
// WebSocket nunca chega a abrir.
const { WebSocketServer } = require("ws");
const { PROTOCOL_PATH, DEFAULT_LIMITS } = require("./protocol");
const { ConnectionRegistry } = require("./registry");
const { Connection } = require("./connection");
const { createHandlers } = require("./handlers");

const STATUS_TEXT = { 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 429: "Too Many Requests", 503: "Service Unavailable" };

const rejectUpgrade = (socket, status, message) => {
  const body = JSON.stringify({ message });
  socket.end(
    `HTTP/1.1 ${status} ${STATUS_TEXT[status]}\r\n` +
      "Connection: close\r\n" +
      "Content-Type: application/json; charset=utf-8\r\n" +
      `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`
  );
};

// Compara a origem (esquema + host + porta) exata; CLIENT_URL ausente ou
// Origin ausente/malformado → recusa (falha fechada).
const isAllowedOrigin = (origin) => {
  try {
    return Boolean(origin) && new URL(origin).origin === new URL(process.env.CLIENT_URL).origin;
  } catch {
    return false;
  }
};

// Roda o middleware de sessão do Express sobre o pedido de upgrade: lê e
// verifica a assinatura do cookie "sid" e carrega a sessão do Postgres.
const loadSession = (sessionMiddleware, req) =>
  new Promise((resolve, reject) => {
    sessionMiddleware(req, {}, (err) => (err ? reject(err) : resolve(req.session)));
  });

const attachRealtime = (server, { session, ...options } = {}) => {
  const limits = { ...DEFAULT_LIMITS, ...options };
  const registry = new ConnectionRegistry();
  const handlers = createHandlers(registry);
  // perMessageDeflate desligado: compressão de dados com segredos abre
  // ataques do tipo CRIME/BREACH, e o ganho aqui seria pequeno.
  // maxPayload: quadro maior é recusado pela própria ws com close 1009,
  // antes de ser acumulado em memória.
  const wss = new WebSocketServer({
    noServer: true,
    perMessageDeflate: false,
    maxPayload: limits.maxPayloadBytes,
  });

  const onUpgrade = async (req, socket, head) => {
    // Erros de rede durante o handshake (cliente desistiu) não derrubam o processo.
    socket.on("error", () => socket.destroy());
    try {
      const { pathname } = new URL(req.url, "http://localhost");
      if (pathname !== PROTOCOL_PATH) return rejectUpgrade(socket, 404, "Não encontrado");
      if (!isAllowedOrigin(req.headers.origin)) return rejectUpgrade(socket, 403, "Origem não permitida");

      const sess = await loadSession(session.middleware, req);
      if (!sess || !Number.isInteger(sess.userId)) return rejectUpgrade(socket, 401, "Não autenticado");
      const { userId } = sess;

      // Checagem e registro sem await no meio: handleUpgrade chama o callback
      // de forma síncrona, então dois upgrades não furam o limite juntos.
      if (registry.countForUser(userId) >= limits.maxConnectionsPerUser) {
        return rejectUpgrade(socket, 429, "Conexões demais para este usuário");
      }
      if (registry.size >= limits.maxConnections) {
        return rejectUpgrade(socket, 503, "Servidor sem vagas de conexão");
      }
      return wss.handleUpgrade(req, socket, head, (ws) => {
        const conn = new Connection(ws, { userId, sid: req.sessionID, limits, handlers });
        registry.add(conn);
        ws.on("close", () => registry.remove(conn));
        ws.on("error", () => ws.terminate());
      });
    } catch (err) {
      console.error("[ws] falha no upgrade:", err.message);
      return rejectUpgrade(socket, 503, "Erro interno");
    }
  };

  server.on("upgrade", onUpgrade);

  return {
    registry,
    close: () => {
      server.off("upgrade", onUpgrade);
      for (const conn of registry.all) conn.socket.terminate();
      wss.close();
    },
  };
};

module.exports = { attachRealtime };
