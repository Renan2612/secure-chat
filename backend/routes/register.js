const pool = require("../db");
const { hashPassword } = require("../helpers/users");

const registerUser = async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  const name = req.body.name;

  // Formato dos campos já validado pelo middleware validate (schemas.register).
  try {
    const hashedPassword = await hashPassword(password, 12);
    const result = await pool.query(
      "INSERT INTO users (email, password, name) VALUES ($1,$2,$3) returning id, email, name",
      [email, hashedPassword, name]
    );
    // Era `res.status(200);` sem .json()/.send() — a resposta nunca era
    // enviada e a requisição ficava pendurada no cliente.
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.log("err", err);
    if (err.code === "23505") {
      return res.status(409).json({ message: "E-mail já cadastrado" });
    }
    res.status(500).json({ message: "Erro ao registrar usuário" });
  }
};

module.exports = { registerUser };
