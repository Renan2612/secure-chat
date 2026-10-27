const bcrypt = require("bcrypt");
const pool = require("../db");
const { cookieOptions, SESSION_COOKIE_NAME } = require("../config/session");

const loginUser = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  pool
    .query("SELECT * FROM users WHERE email = $1", [email])
    .then((result) => result.rows)
    .then((users) => {
      if (users.length !== 1) {
        return res.status(404).json({ message: "Usuário não encontrado" });
      }
      bcrypt.compare(password, users[0].password, (err, result) => {
        if (err) {
          console.log("err", err);
          return res.status(500).json({ message: "Erro ao autenticar" });
        }
        if (result) {
          // Troca o ID da sessão no login: um ID plantado antes da
          // autenticação (session fixation) deixa de valer.
          return req.session.regenerate((regenErr) => {
            if (regenErr) return next(regenErr);
            req.session.userId = users[0].id;
            return req.session.save((saveErr) => {
              if (saveErr) return next(saveErr);
              return res.status(201).json({ message: "saves" });
            });
          });
        }
        // Era um "else" vazio: a requisição ficava pendurada sem resposta.
        return res.status(401).json({ message: "Senha incorreta" });
      });
    })
    .catch((err) => {
      console.log("err", err);
      res.status(500).json({ message: "Erro ao autenticar" });
    });
};

// CORRIGIDO: esta rota devolvia a linha inteira de `users`, incluindo o
// HASH DA SENHA, para qualquer requisição com um e-mail. Agora devolve
// apenas se o e-mail existe, sem nenhum dado do usuário.
const checkUserExists = (req, res) => {
  const email = req.body.email;
  pool
    .query("SELECT id FROM users WHERE email = $1", [email])
    .then((result) => result.rows)
    .then((users) => {
      res.status(200).json({ exists: users.length > 0 });
    })
    .catch((err) => {
      console.log("err", err);
      res.status(500).json({ message: "Erro ao verificar usuário" });
    });
};

// Apaga a sessão no servidor (revogação real: um cookie copiado deixa de
// funcionar) e pede ao navegador para descartar o cookie.
const logoutUser = (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie(SESSION_COOKIE_NAME, cookieOptions());
    return res.status(204).send();
  });
};

module.exports = { loginUser, logoutUser, checkUserExists };
