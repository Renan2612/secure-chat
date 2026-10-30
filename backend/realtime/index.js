// Canal em tempo real: protocolo próprio sobre WebSocket (RFC 6455) no
// caminho /ws do mesmo servidor HTTP. Substitui o Socket.IO, que aceitava
// qualquer conexão e fazia broadcast global (itens A e B do baseline).
//
// O upgrade HTTP → WebSocket só é aceito depois de, nesta ordem:
//   1. caminho == /ws                          (senão 404)
//   2. ritmo de tentativas do IP real          (senão 429, sem tocar no banco)
//   3. Origin == CLIENT_URL                    (senão 403 — Cross-Site WebSocket Hijacking)
//   4. cookie "sid" com sessão válida no store e não revogada durante a
//      leitura                                 (senão 401 — mesma sessão da API)
//   5. quarentena após close 4429 (429) e limites de conexões (por usuário:
//      429; total: 503)
// Recusas respondem HTTP com corpo JSON genérico e fecham o TCP: o socket
// WebSocket nunca chega a abrir.
const { WebSocketServer } = require("ws");
const proxyaddr = require("proxy-addr");
const { PROTOCOL_PATH, DEFAULT_LIMITS, CLOSE } = require("./protocol");
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

// trustProxy: a função de confiança que o Express compilou a partir de
// TRUST_PROXY (app.get("trust proxy fn")); o IP do upgrade é calculado com a
// MESMA regra das rotas HTTP. Sem ela, não confia em nenhum proxy.
const attachRealtime = (server, { session, trustProxy = proxyaddr.compile([]), ...options } = {}) => {
  const limits = { ...DEFAULT_LIMITS, ...options };
  const registry = new ConnectionRegistry();
  const { handlers, notifyKeyPending, notifyKeyReady, notifyRemoved, notifyRotationPending, notifyKeyRotated } = createHandlers(registry);
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
      if (!registry.takeUpgradeToken(proxyaddr(req, trustProxy), limits.upgradeBurst, limits.upgradeRefillPerSec)) {
        return rejectUpgrade(socket, 429, "Tentativas de conexão demais; aguarde");
      }
      if (!isAllowedOrigin(req.headers.origin)) return rejectUpgrade(socket, 403, "Origem não permitida");

      // Um logout que aconteça enquanto a sessão é lida (await abaixo) não
      // pode deixar passar este upgrade com a sessão já revogada.
      const revocationMark = registry.revocations;
      const sess = await loadSession(session.middleware, req);
      if (!sess || !Number.isInteger(sess.userId)) return rejectUpgrade(socket, 401, "Não autenticado");
      const { userId } = sess;
      if (registry.revokedSince(userId, revocationMark)) return rejectUpgrade(socket, 401, "Não autenticado");

      // Checagem e registro sem await no meio: handleUpgrade chama o callback
      // de forma síncrona, então dois upgrades não furam o limite juntos.
      if (registry.inCooldown(userId)) {
        return rejectUpgrade(socket, 429, "Pacotes demais; tente novamente mais tarde");
      }
      if (registry.countForUser(userId) >= limits.maxConnectionsPerUser) {
        return rejectUpgrade(socket, 429, "Conexões demais para este usuário");
      }
      if (registry.size >= limits.maxConnections) {
        return rejectUpgrade(socket, 503, "Servidor sem vagas de conexão");
      }
      return wss.handleUpgrade(req, socket, head, (ws) => {
        // O 101 já foi enviado: daqui em diante uma falha não pode virar
        // resposta HTTP (cairia no meio do fluxo WebSocket). Derruba o socket.
        let conn;
        try {
          conn = new Connection(ws, {
            userId,
            sid: req.sessionID,
            limits,
            handlers,
            onRateLimited: () => registry.startCooldown(userId, limits.rateLimitCooldownMs),
          });
          registry.add(conn);
        } catch (err) {
          console.error(`[ws] falha ao registrar conexão: ${err.message}`);
          if (conn) registry.remove(conn);
          ws.terminate();
          return;
        }
        ws.on("close", () => registry.remove(conn));
        // Erros de protocolo (quadro grande demais, UTF-8 inválido, opcode
        // desconhecido) são sinais de abuso: registra só o código, nunca o quadro.
        ws.on("error", (err) => {
          console.error(`[ws] erro de protocolo user=${userId} code=${err.code ?? "-"}`);
          ws.terminate();
        });
      });
    } catch (err) {
      console.error("[ws] falha no upgrade:", err.message);
      return rejectUpgrade(socket, 503, "Erro interno");
    }
  };

  server.on("upgrade", onUpgrade);

  const getSession = (sid) =>
    new Promise((resolve, reject) => {
      session.store.get(sid, (err, sess) => (err ? reject(err) : resolve(sess)));
    });

  // Sessões que terminaram sem passar pelo logout (expiraram, foram apagadas
  // do banco, logout em outra instância): fecha as conexões delas com 4401.
  // Se o store falhar (banco fora), mantém as conexões: o banco fora já
  // impede gravar e autorizar, e derrubar todos agravaria a indisponibilidade.
  const revalidateSessions = async () => {
    const bySid = new Map();
    for (const conn of registry.all) {
      if (!bySid.has(conn.sid)) bySid.set(conn.sid, []);
      bySid.get(conn.sid).push(conn);
    }
    for (const [sid, conns] of bySid) {
      try {
        const sess = await getSession(sid);
        for (const conn of conns) {
          if (sess?.userId !== conn.userId) conn.close(CLOSE.SESSION_ENDED, "sessão encerrada");
        }
      } catch (err) {
        console.error("[ws] falha ao revalidar sessão:", err.message);
      }
    }
  };

  // Uma revalidação lenta (muitas sessões, banco devagar) não se sobrepõe à
  // próxima, para não empilhar consultas no pool.
  let revalidating = false;
  const heartbeat = setInterval(() => {
    for (const conn of registry.all) {
      if (!conn.alive) {
        conn.socket.terminate(); // morta: sem handshake de fechamento
        continue;
      }
      conn.alive = false;
      conn.socket.ping();
    }
    registry.sweepUpgradeBuckets();
    if (revalidating) return;
    revalidating = true;
    revalidateSessions()
      .catch((err) => console.error("[ws] falha na revalidação de sessões:", err.message))
      .finally(() => {
        revalidating = false;
      });
  }, limits.heartbeatIntervalMs);
  heartbeat.unref();

  // Chamados pelas rotas HTTP sem esperar: uma falha aqui só perde o aviso
  // (o cliente também descobre pendências ao se inscrever).
  // Recebe uma FUNÇÃO: um erro síncrono também vira só log (nunca um 500 de
  // uma operação já gravada, nem impede os avisos seguintes).
  const fireAndLog = (what, fn) =>
    Promise.resolve()
      .then(fn)
      .catch((err) => console.error(`[ws] falha ao avisar ${what}: ${err.message}`));

  return {
    registry,
    notify: {
      keyPending: (room) => fireAndLog("KEY_PENDING", () => notifyKeyPending(room)),
      keyReady: (userId, room) => fireAndLog("KEY_READY", () => notifyKeyReady(userId, room)),
      removed: (userId, room) => fireAndLog("REMOVED", () => notifyRemoved(userId, room)),
      rotationPending: (room) => fireAndLog("ROTATION_PENDING", () => notifyRotationPending(room)),
      keyRotated: (room) => fireAndLog("KEY_ROTATED", () => notifyKeyRotated(room)),
    },
    // Fim da sessão (logout): fecha todas as conexões do usuário.
    closeUser: (userId) => {
      registry.revoke(userId);
      for (const conn of registry.forUser(userId)) conn.close(CLOSE.SESSION_ENDED, "sessão encerrada");
    },
    close: () => {
      clearInterval(heartbeat);
      server.off("upgrade", onUpgrade);
      for (const conn of registry.all) conn.socket.terminate();
      wss.close();
    },
  };
};

module.exports = { attachRealtime };
