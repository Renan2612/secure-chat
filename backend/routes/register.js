const pool = require("../db");
const { hashPassword } = require("../helpers/users");

const UNIQUE_VIOLATION = "23505";

const registerUser = async (req, res, next) => {
  // Formato dos campos já validado (e e-mail normalizado) pelo middleware
  // validate (schemas.register).
  const { email, password, name } = req.body;

  try {
    const hashedPassword = await hashPassword(password, 12);
    const result = await pool.query(
      "INSERT INTO users (email, password, name) VALUES ($1,$2,$3) returning id, email, name",
      [email, hashedPassword, name]
    );
    // Era `res.status(200);` sem .json()/.send() — a resposta nunca era
    // enviada e a requisição ficava pendurada no cliente.
    return res.status(201).json(result.rows[0]);
  } catch (err) {
    // LIMITAÇÃO CONHECIDA: o 409 revela que o e-mail já tem conta. Evitar
    // isso exige confirmação por e-mail (fora do escopo); por ora a rota tem
    // rate limit. Ver docs/02-autenticacao-autorizacao.md.
    if (err.code === UNIQUE_VIOLATION) {
      return res.status(409).json({ message: "E-mail já cadastrado" });
    }
    return next(err);
  }
};

module.exports = { registerUser };
