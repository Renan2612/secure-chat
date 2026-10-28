// Montagem da aplicação Express, separada do servidor HTTP/WebSocket
// (createServer.js) para que os testes possam usar o app sem abrir porta.
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { createSession } = require("./config/session");

const { registerUser } = require("./routes/register");
const { loginUser, logoutUser } = require("./routes/login");
const {
  getRooms,
  createRooms,
  checkRoomExists,
  joinRooms,
  roomsUsers,
} = require("./routes/rooms");
const { getMessages, updateLastRead } = require("./routes/messages");
const requireAuth = require("./middleware/requireAuth");
const requireRoomMember = require("./middleware/requireRoomMember");
const validate = require("./middleware/validate");
const schemas = require("./validation/schemas");
const { notFound, errorHandler } = require("./middleware/errorHandler");
const pool = require("./db");

// Também verifica o banco: sem ele, toda rota útil falharia, e o
// orquestrador (Docker/proxy) precisa saber para não mandar tráfego.
const healthCheck = async (req, res) => {
  try {
    await pool.query("SELECT 1");
    return res.status(200).json({ status: "ok" });
  } catch (err) {
    console.error("[health] banco indisponível:", err.message);
    return res.status(503).json({ status: "indisponível" });
  }
};

// Número de proxies reversos na frente do app (Caddy = 1). Só um inteiro
// >= 1: "true" faria o Express confiar em QUALQUER X-Forwarded-For (o
// cliente escolheria o próprio IP no rate limit), e listas/nomes ("loopback")
// mudam o modelo de confiança em silêncio. Valor inválido → não sobe.
const trustProxyHops = () => {
  const raw = process.env.TRUST_PROXY;
  if (raw === undefined || raw === "") return null;
  if (!/^[1-9][0-9]*$/.test(raw)) {
    throw new Error("TRUST_PROXY deve ser um inteiro >= 1 (número de proxies reversos na frente do backend)");
  }
  return Number(raw);
};

// onSessionEnd(userId): chamado quando uma sessão termina por logout, para o
// canal em tempo real derrubar as conexões abertas daquele usuário.
const createApp = ({
  authRateLimitMax = 20,
  loginEmailRateLimitMax = 10,
  session = createSession(),
  onSessionEnd = () => {},
} = {}) => {
  const app = express();

  // Atrás de um proxy reverso (nginx, Traefik...) o Express só enxerga HTTP
  // vindo do proxy; sem isso, req.secure é falso e o cookie Secure não é
  // emitido, e o rate limit veria o IP do proxy em vez do IP do cliente.
  // TRUST_PROXY = número de proxies na frente do app (ex.: 1). Não habilitar
  // sem proxy: o cliente poderia forjar X-Forwarded-For.
  const hops = trustProxyHops();
  // Em produção o backend só existe atrás do proxy TLS: sem TRUST_PROXY, o
  // Express acharia toda conexão HTTP e nunca emitiria o cookie Secure (o
  // login "funcionaria" sem sessão). Melhor não subir.
  if (hops === null && process.env.NODE_ENV === "production") {
    throw new Error("NODE_ENV=production exige TRUST_PROXY (número de proxies reversos na frente do backend)");
  }
  if (hops !== null) app.set("trust proxy", hops);

  // --- Segurança de cabeçalhos HTTP ---
  // HSTS fica com o proxy TLS (Caddy), que vê a conexão HTTPS e cobre todas
  // as respostas da origem; emitir aqui também duplicaria o cabeçalho.
  // Os demais (nosniff, CSP, Referrer-Policy...) das respostas da API vêm
  // daqui (docs/04-tls-e-proxy.md).
  app.use(helmet({ strictTransportSecurity: false }));

  // --- CORS restrito à origem do frontend ---
  app.use(
    cors({
      origin: process.env.CLIENT_URL,
      credentials: true,
    })
  );

  // --- Limite de tamanho do corpo da requisição ---
  app.use(express.json({ limit: "10kb" }));

  // --- Sessão armazenada no servidor (Postgres) ---
  app.use(session.middleware);
  app.locals.onSessionEnd = onSessionEnd;

  // --- Rate limiting em rotas sensíveis (login/registro) ---
  const limiterDefaults = {
    windowMs: 15 * 60 * 1000,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: "Muitas tentativas. Tente novamente em instantes." },
  };

  const authLimiter = rateLimit({ ...limiterDefaults, max: authRateLimitMax });

  // Segundo limite, só no login, por CONTA (e-mail normalizado) em vez de
  // por IP: freia força bruta distribuída contra uma conta específica a
  // partir de muitos IPs. Roda depois do validate, que normaliza o e-mail.
  // Conta só tentativas FALHAS, para o uso legítimo não gastar a cota.
  // Efeito colateral aceito: um atacante ainda pode travar o login de uma
  // conta por 15 min errando a senha de propósito (ver docs/02).
  const loginEmailLimiter = rateLimit({
    ...limiterDefaults,
    max: loginEmailRateLimitMax,
    // Só senha/e-mail errados (401) contam: erros do servidor (500), como
    // uma queda do banco, não podem travar a conta do dono depois.
    skipSuccessfulRequests: true,
    requestWasSuccessful: (req, res) => res.statusCode !== 401,
    keyGenerator: (req) => `login:${req.body.email}`,
  });

  // --- Rotas públicas (as únicas acessíveis sem sessão) ---
  app.get("/health", healthCheck);
  app.post("/register", authLimiter, validate(schemas.register), registerUser);
  app.post("/login", authLimiter, validate(schemas.login), loginEmailLimiter, loginUser);

  // --- Daqui para baixo, tudo exige sessão autenticada ---
  app.use(requireAuth);

  app.get("/rooms", getRooms);
  app.post("/logout", logoutUser); // era GET: logout por GET permite CSRF via <img>/<a>
  app.get("/messages/:id", validate(schemas.getMessages), requireRoomMember, getMessages);
  // POST /messages foi REMOVIDO na Etapa 3: o envio é só por MSG_SEND no
  // WebSocket (/ws), que grava e entrega — um único caminho para autorizar.
  app.post(
    "/updateLastViewed",
    validate(schemas.updateLastViewed),
    requireRoomMember,
    updateLastRead
  );
  app.post("/checkRoomExists", validate(schemas.checkRoomExists), checkRoomExists);
  app.post("/createRoom", validate(schemas.createRoom), createRooms);
  app.post("/joinRooms", validate(schemas.joinRooms), joinRooms);
  app.get("/roomUsers/:room", validate(schemas.roomUsers), requireRoomMember, roomsUsers);

  // As rotas de debug /session, /sessionRoom e /session (POST) foram REMOVIDAS.
  // A rota POST /session permitia que qualquer cliente definisse req.session.userId
  // manualmente — ou seja, se passar por qualquer usuário sem autenticar.
  // Ver docs/01-baseline-seguranca.md para o registro completo.

  app.use(notFound);
  app.use(errorHandler);

  return app;
};

module.exports = { createApp };
