const bcrypt = require("bcrypt");

const PRODUCTION_COST = 12;

// Custo do bcrypt. Fixo em 12 em qualquer ambiente real; só a suíte de
// testes (NODE_ENV=test) pode reduzi-lo via BCRYPT_COST, porque cada
// cadastro/login de teste pagaria ~250 ms de CPU.
const bcryptCost = (env = process.env) =>
  env.NODE_ENV === "test" && env.BCRYPT_COST ? Number(env.BCRYPT_COST) : PRODUCTION_COST;

const BCRYPT_COST = bcryptCost();

const hashPassword = (password) => bcrypt.hash(password, BCRYPT_COST);

module.exports = { hashPassword, bcryptCost, BCRYPT_COST };
