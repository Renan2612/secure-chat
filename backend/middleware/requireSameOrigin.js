// Proteção contra CSRF (Etapa 5, A2), em TODA requisição que muda estado
// (POST, PUT, PATCH, DELETE), inclusive /login e /register:
//   - Origin obrigatório e igual à origem configurada (CLIENT_URL). Sem
//     Origin, ou de outro site → 403. O cookie é SameSite=Lax (não vai em
//     POST de outro site), mas a checagem não depende do navegador acertar
//     o "site" (subdomínios, navegadores antigos, extensões).
//   - Corpo só em JSON: um formulário HTML entre sites só manda
//     application/x-www-form-urlencoded, multipart/form-data ou text/plain
//     sem preflight. Com corpo (ou Content-Type declarado) que não seja
//     application/json → 415. Requisição sem corpo (logout, sair da sala)
//     passa só pela checagem de Origin.
// GET e HEAD não mudam estado (e não passam por aqui).
const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

const originOf = (value) => {
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
};

// Só o tipo, sem parâmetros (charset) e sem diferenciar maiúsculas.
const isJson = (contentType) => contentType.split(";")[0].trim().toLowerCase() === "application/json";

const requireSameOrigin = (allowedOrigin = process.env.CLIENT_URL) => {
  const allowed = originOf(allowedOrigin);
  if (!allowed) throw new Error("CLIENT_URL precisa ser uma URL (a origem do frontend) para a checagem de Origin");
  return (req, res, next) => {
    if (!UNSAFE.has(req.method)) return next();
    const origin = req.get("Origin");
    // Comparação exata com a origem serializada (esquema://host[:porta]):
    // o navegador manda o Origin assim, sem caminho nem barra no fim.
    if (origin !== allowed) {
      return res.status(403).json({ message: "Origem não permitida" });
    }
    const declared = req.get("Content-Type");
    const hasBody = Number(req.get("Content-Length") ?? 0) > 0 || req.get("Transfer-Encoding") !== undefined;
    if ((hasBody || declared !== undefined) && !(declared !== undefined && isJson(declared))) {
      return res.status(415).json({ message: "Use Content-Type: application/json" });
    }
    return next();
  };
};

module.exports = { requireSameOrigin };
