// Barra qualquer requisição sem sessão autenticada. É registrado de forma
// global no app.js, depois das rotas públicas: assim toda rota nova nasce
// protegida, e esquecer de aplicar o middleware não abre um buraco.
const requireAuth = (req, res, next) => {
  if (!req.session || !Number.isInteger(req.session.userId)) {
    return res.status(401).json({ message: "Não autenticado" });
  }
  return next();
};

module.exports = requireAuth;
