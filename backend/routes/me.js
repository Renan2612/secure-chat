const pool = require("../db");

// GET /me (Etapa 5, B-D3): id e nome de quem está logado, para o frontend
// retomar a sessão ao recarregar. Sem e-mail nem nada além do necessário.
// Conta que não existe mais (sessão órfã) → 401, como sem sessão.
const getMe = async (req, res, next) => {
  try {
    const { rows } = await pool.query("SELECT id, name FROM users WHERE id = $1", [req.session.userId]);
    if (rows.length === 0) return res.status(401).json({ message: "Não autenticado" });
    return res.status(200).json({ id: rows[0].id, name: rows[0].name });
  } catch (err) {
    return next(err);
  }
};

module.exports = { getMe };
