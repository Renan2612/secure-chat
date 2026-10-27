// Tratamento central de rotas inexistentes e de erros.
//
// Respostas ao cliente são sempre genéricas: nada de stack trace, mensagem
// do Postgres ou nome de tabela. No log vai o necessário para depurar —
// stack (arquivo/linha) e metadados de schema do pg (constraint, tabela,
// coluna) — mas nunca o corpo da requisição (senhas), cabeçalhos (cookie de
// sessão) nem err.detail do pg, que costuma conter os valores das colunas.
// Cuidado: algumas mensagens do pg citam a entrada (ex.: 22P02 "invalid input
// syntax for type integer: ..."); a validação (zod) impede que isso ocorra
// hoje, mas uma lacuna futura no schema poderia levar entrada ao log.

const notFound = (req, res) => res.status(404).json({ message: "Não encontrado" });

// Erros do cliente com mensagem própria; os demais 4xx levam a genérica.
const clientMessages = {
  "entity.too.large": "Requisição muito grande",
};

const PG_SCHEMA_FIELDS = ["constraint", "table", "column", "routine"];

// eslint-disable-next-line no-unused-vars -- o Express reconhece o handler de erro pelos 4 parâmetros
const errorHandler = (err, req, res, next) => {
  // Erros do cliente sinalizados pelo body-parser/Express (JSON malformado,
  // charset não suportado, parâmetro de URL malformado...): não são falhas
  // internas, então não vão para o log de erro.
  const status = err.status || err.statusCode;
  if (status >= 400 && status < 500) {
    return res.status(status).json({ message: clientMessages[err.type] || "Requisição inválida" });
  }

  const pgFields = PG_SCHEMA_FIELDS.filter((field) => err[field])
    .map((field) => `${field}=${err[field]}`)
    .join(" ");
  console.error(
    `[erro] ${new Date().toISOString()} ${req.method} ${req.route ? req.route.path : req.path}` +
      `${err.code ? ` code=${err.code}` : ""}${pgFields ? ` ${pgFields}` : ""}\n${err.stack}`
  );
  if (res.headersSent) return undefined;
  return res.status(500).json({ message: "Erro interno" });
};

module.exports = { notFound, errorHandler };
