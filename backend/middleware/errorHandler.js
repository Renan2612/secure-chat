// Tratamento central de rotas inexistentes e de erros.
//
// Respostas ao cliente são sempre genéricas: nada de stack trace, mensagem
// do Postgres ou nome de tabela. No log vai só o necessário para depurar
// (método, rota, tipo/código e mensagem do erro) — nunca o corpo da
// requisição (senhas), cabeçalhos (cookie de sessão) nem err.detail do pg,
// que costuma conter os valores das colunas.

const notFound = (req, res) => res.status(404).json({ message: "Não encontrado" });

// Erros lançados pelo express.json() antes de chegar às rotas.
const clientErrors = {
  "entity.parse.failed": [400, "Requisição inválida"],
  "entity.too.large": [413, "Requisição muito grande"],
};

// eslint-disable-next-line no-unused-vars -- o Express reconhece o handler de erro pelos 4 parâmetros
const errorHandler = (err, req, res, next) => {
  const clientError = clientErrors[err.type];
  if (clientError) {
    const [status, message] = clientError;
    return res.status(status).json({ message });
  }

  console.error(
    `[erro] ${req.method} ${req.route ? req.route.path : req.path} —`,
    `${err.name}${err.code ? ` (${err.code})` : ""}: ${err.message}`
  );
  if (res.headersSent) return undefined;
  return res.status(500).json({ message: "Erro interno" });
};

module.exports = { notFound, errorHandler };
