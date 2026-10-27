// Sessão armazenada no servidor (Postgres), substituindo o cookie-session.
//
// Com cookie-session, os dados da sessão viajavam assinados DENTRO do cookie:
// o servidor não tinha como invalidar um cookie já emitido (um cookie copiado
// continuava válido até expirar, mesmo após o logout). Agora o cookie carrega
// só um ID aleatório assinado, e os dados ficam na tabela user_sessions —
// apagar a linha revoga a sessão imediatamente.
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const pool = require("../db");

const SESSION_COOKIE_NAME = "sid"; // genérico: não anuncia o framework
const SESSION_MAX_AGE_MS = 8 * 60 * 60 * 1000; // 8 horas
const MIN_SECRET_LENGTH = 32;

const isProduction = () => process.env.NODE_ENV === "production";

// Atributos do cookie compartilhados entre a criação (express-session) e a
// remoção no logout (res.clearCookie) — precisam bater para o navegador apagar.
const cookieOptions = () => ({
  httpOnly: true, // inacessível ao JavaScript da página (mitiga roubo via XSS)
  sameSite: "lax", // não é enviado em POSTs vindos de outros sites (mitiga CSRF)
  secure: isProduction(), // só trafega por HTTPS em produção
  path: "/",
});

const readSecrets = () => {
  const current = process.env.SESSION_SECRET;
  if (!current || current.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `SESSION_SECRET ausente ou curto demais (mínimo ${MIN_SECRET_LENGTH} caracteres). ` +
        "Gere um com: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\""
    );
  }
  // Rotação: o primeiro segredo assina cookies novos; os demais ainda são
  // aceitos na verificação, para não derrubar sessões ativas na troca.
  const previous = process.env.SESSION_SECRET_PREVIOUS;
  return previous ? [current, previous] : [current];
};

// Cria o store e o middleware juntos: o canal em tempo real (/ws) usa o
// MESMO middleware para autenticar o upgrade e o MESMO store para revalidar
// a sessão das conexões abertas — uma única fonte de verdade para "logado".
const createSession = () => {
  const store = new PgSession({
    pool,
    tableName: "user_sessions",
    // Limpeza periódica de sessões expiradas. Desligada nos testes para
    // não deixar timers abertos que impedem o jest de encerrar.
    pruneSessionInterval: process.env.NODE_ENV === "test" ? false : 15 * 60,
  });
  const middleware = session({
    name: SESSION_COOKIE_NAME,
    secret: readSecrets(),
    store,
    resave: false,
    saveUninitialized: false, // nenhuma sessão/cookie para visitante anônimo
    cookie: { ...cookieOptions(), maxAge: SESSION_MAX_AGE_MS },
  });
  return { middleware, store };
};

module.exports = { createSession, cookieOptions, SESSION_COOKIE_NAME };
