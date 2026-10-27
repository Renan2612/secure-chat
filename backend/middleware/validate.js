// Valida corpo e/ou parâmetros da rota contra um schema zod e substitui-os
// pela versão validada (tipos convertidos, campos extras descartados).
// A resposta de erro é genérica: não ecoa a entrada nem detalha a regra.
const validate =
  ({ body, params }) =>
  (req, res, next) => {
    const parsedBody = body ? body.safeParse(req.body ?? {}) : null;
    const parsedParams = params ? params.safeParse(req.params) : null;
    if ((parsedBody && !parsedBody.success) || (parsedParams && !parsedParams.success)) {
      return res.status(400).json({ message: "Requisição inválida" });
    }
    if (parsedBody) req.body = parsedBody.data;
    if (parsedParams) Object.assign(req.params, parsedParams.data);
    return next();
  };

module.exports = validate;
