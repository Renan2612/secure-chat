// Carregado primeiro: qualquer módulo abaixo que leia process.env precisa
// encontrar as variáveis já disponíveis.
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieSession = require("cookie-session");
const rateLimit = require("express-rate-limit");
const http = require("http");
const { Server } = require("socket.io");

const { registerUser } = require("./routes/register");
const { loginUser, checkUserExists, logoutUser } = require("./routes/login");
const {
  getRooms,
  createRooms,
  checkRoomExists,
  listRoomsNotInto,
  joinRooms,
  roomsUsers,
} = require("./routes/rooms");
const { getMessages, postMessages, updateLastRead } = require("./routes/messages");

const app = express();

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

// --- Sessão (cookie assinado) ---
// NOTA (Etapa 2): migrar para sessão armazenada no servidor (ex.: connect-pg-simple)
// para permitir revogação de sessões e evitar guardar dados no cliente.
app.use(
  cookieSession({
    name: "session",
    keys: [process.env.SESSION_KEY_1, process.env.SESSION_KEY_2],
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
  })
);

// --- Rate limiting em rotas sensíveis (login/registro) ---
// NOTA: ajustar limites conforme necessidade real do projeto na Etapa 2.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Muitas tentativas. Tente novamente em instantes." },
});

// --- Rotas HTTP ---
// IMPORTANTE (Etapa 2): nenhuma destas rotas verifica autenticação nem
// pertencimento à sala ainda. Isso é tratado na Etapa 2 com middleware
// dedicado. Ver docs/01-baseline-seguranca.md.
app.get("/rooms", getRooms);
app.post("/register", authLimiter, registerUser);
app.post("/login", authLimiter, loginUser);
app.post("/logout", logoutUser); // era GET: logout por GET permite CSRF via <img>/<a>
app.post("/checkUserExists", checkUserExists);
app.get("/messages/:id", getMessages);
app.post("/messages", postMessages);
app.post("/updateLastViewed", updateLastRead);
app.post("/checkRoomExists", checkRoomExists);
app.post("/createRoom", createRooms);
app.get("/listRoomsNotInto", listRoomsNotInto);
app.post("/joinRooms", joinRooms);
app.get("/roomUsers/:room", roomsUsers);

// As rotas de debug /session, /sessionRoom e /session (POST) foram REMOVIDAS.
// A rota POST /session permitia que qualquer cliente definisse req.session.userId
// manualmente — ou seja, se passar por qualquer usuário sem autenticar.
// Ver docs/01-baseline-seguranca.md para o registro completo.

// --- Servidor HTTP + Socket.IO ---
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL,
    methods: ["GET", "POST"], // era "method" (singular): não tinha efeito nenhum
  },
});

// ATENÇÃO (Etapa 3): este socket ainda não autentica a conexão, não usa salas
// (io.join) e usa broadcast global — qualquer cliente conectado recebe as
// mensagens de todas as salas, e o remetente não é validado pelo servidor.
// Esta é a prioridade da Etapa 3 e não foi alterada aqui de propósito, para
// preservar o comportamento "antes" como linha de base de comparação.
io.on("connection", (socket) => {
  socket.on("send_message", (data) => {
    socket.broadcast.emit("receive_message", data);
  });
});

const PORT = process.env.SERVER_PORT || 8000;
server.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
