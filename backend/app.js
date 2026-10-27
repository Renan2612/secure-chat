// Montagem da aplicação Express, separada do server.js para que os testes
// (supertest) possam usar o app sem abrir porta nem subir o Socket.IO.
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { createSessionMiddleware } = require("./config/session");

const { registerUser } = require("./routes/register");
const { loginUser, checkUserExists, logoutUser } = require("./routes/login");
const {
  getRooms,
  createRooms,
  checkRoomExists,
  joinRooms,
  roomsUsers,
} = require("./routes/rooms");
const { getMessages, postMessages, updateLastRead } = require("./routes/messages");
const requireAuth = require("./middleware/requireAuth");
const requireRoomMember = require("./middleware/requireRoomMember");
const validate = require("./middleware/validate");
const schemas = require("./validation/schemas");

const createApp = ({ authRateLimitMax = 20 } = {}) => {
  const app = express();

  // Atrás de um proxy reverso (nginx, Traefik...) o Express só enxerga HTTP
  // vindo do proxy; sem isso, req.secure é falso e o cookie Secure não é
  // emitido, e o rate limit veria o IP do proxy em vez do IP do cliente.
  // TRUST_PROXY = número de proxies na frente do app (ex.: 1). Não habilitar
  // sem proxy: o cliente poderia forjar X-Forwarded-For.
  if (process.env.TRUST_PROXY) {
    const hops = Number(process.env.TRUST_PROXY);
    app.set("trust proxy", Number.isInteger(hops) ? hops : process.env.TRUST_PROXY);
  }

  // --- Segurança de cabeçalhos HTTP ---
  app.use(helmet());

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
  app.use(createSessionMiddleware());

  // --- Rate limiting em rotas sensíveis (login/registro) ---
  // NOTA: ajustar limites conforme necessidade real do projeto na Etapa 2.
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: authRateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: "Muitas tentativas. Tente novamente em instantes." },
  });

  // --- Rotas públicas (as únicas acessíveis sem sessão) ---
  app.get("/health", (req, res) => res.status(200).json({ status: "ok" }));
  app.post("/register", authLimiter, validate(schemas.register), registerUser);
  app.post("/login", authLimiter, validate(schemas.login), loginUser);

  // --- Daqui para baixo, tudo exige sessão autenticada ---
  app.use(requireAuth);

  app.get("/rooms", getRooms);
  app.post("/logout", logoutUser); // era GET: logout por GET permite CSRF via <img>/<a>
  app.post("/checkUserExists", checkUserExists);
  app.get("/messages/:id", validate(schemas.getMessages), requireRoomMember, getMessages);
  app.post("/messages", validate(schemas.postMessage), requireRoomMember, postMessages);
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

  return app;
};

module.exports = { createApp };
