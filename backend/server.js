// Carregado primeiro: qualquer módulo abaixo que leia process.env precisa
// encontrar as variáveis já disponíveis.
require("dotenv").config();

const http = require("http");
const { Server } = require("socket.io");

const { createApp } = require("./app");

const app = createApp();

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
