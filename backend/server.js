// Carregado primeiro: qualquer módulo abaixo que leia process.env precisa
// encontrar as variáveis já disponíveis.
require("dotenv").config();

const { createServer } = require("./createServer");

// O Socket.IO foi REMOVIDO na Etapa 3: aceitava conexões sem autenticação e
// fazia broadcast global de todas as salas. O tempo real agora é um
// protocolo próprio sobre WebSocket em /ws (realtime/, docs/03-protocolo.md).
const { server } = createServer();

const PORT = process.env.SERVER_PORT || 8000;
server.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
