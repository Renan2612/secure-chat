const bcrypt = require("bcrypt");
const pool = require("../db");
const { cookieOptions, SESSION_COOKIE_NAME } = require("../config/session");

// Hash bcrypt (custo 12, o mesmo do cadastro) de uma senha aleatória
// descartada. Quando o e-mail não existe, o login compara a senha contra ele
// só para gastar o mesmo tempo de uma conta real: sem isso, a resposta para
// "e-mail inexistente" saía ~100x mais rápida e revelava quais contas existem.
const DUMMY_HASH = "$2b$12$Cv3IAqZsRwB5vmi56Cknfur/J/Z140DXSk1s9wEq98nc32h98N8t.";

// "E-mail não existe" e "senha errada" recebem exatamente a mesma resposta
// (status, corpo e tempo), para não permitir enumeração de usuários.
const INVALID_CREDENTIALS = { message: "Credenciais inválidas" };

const loginUser = async (req, res, next) => {
  const { email, password } = req.body; // e-mail já normalizado pelo validate

  try {
    const { rows } = await pool.query("SELECT id, name, password FROM users WHERE email = $1", [
      email,
    ]);
    const user = rows[0];
    const passwordMatches = await bcrypt.compare(password, user ? user.password : DUMMY_HASH);
    if (!user || !passwordMatches) {
      return res.status(401).json(INVALID_CREDENTIALS);
    }

    // Troca o ID da sessão no login: um ID plantado antes da
    // autenticação (session fixation) deixa de valer.
    return req.session.regenerate((regenErr) => {
      if (regenErr) return next(regenErr);
      req.session.userId = user.id;
      return req.session.save((saveErr) => {
        if (saveErr) {
          // Descarta a sessão já marcada como autenticada: sem isso, o
          // express-session ainda enviaria o cookie e tentaria gravá-la de
          // novo no fim da resposta — o cliente veria "erro" mas poderia
          // ficar logado.
          req.session = null;
          return next(saveErr);
        }
        return res.status(200).json({ id: user.id, name: user.name });
      });
    });
  } catch (err) {
    return next(err);
  }
};

// REMOVIDO: checkUserExists. Respondia se um e-mail tinha conta, para
// qualquer um — enumeração de usuários. O cadastro já informa e-mail
// duplicado (409), então a rota não era essencial.

// Apaga a sessão no servidor (revogação real: um cookie copiado deixa de
// funcionar) e pede ao navegador para descartar o cookie.
const logoutUser = (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie(SESSION_COOKIE_NAME, cookieOptions());
    return res.status(204).send();
  });
};

module.exports = { loginUser, logoutUser };
