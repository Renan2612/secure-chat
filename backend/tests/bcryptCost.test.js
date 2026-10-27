// O custo do bcrypt só pode ser reduzido na suíte de testes (para ela rodar
// em tempo razoável). Em qualquer outro ambiente ele é fixo em 12.
const { bcryptCost } = require("../helpers/users");

test("fora de NODE_ENV=test, BCRYPT_COST é ignorado e o custo é 12", () => {
  expect(bcryptCost({ NODE_ENV: "production", BCRYPT_COST: "4" })).toBe(12);
  expect(bcryptCost({ NODE_ENV: "development", BCRYPT_COST: "4" })).toBe(12);
  expect(bcryptCost({ BCRYPT_COST: "4" })).toBe(12);
});

test("em NODE_ENV=test o custo pode ser reduzido", () => {
  expect(bcryptCost({ NODE_ENV: "test", BCRYPT_COST: "4" })).toBe(4);
  expect(bcryptCost({ NODE_ENV: "test" })).toBe(12);
});

test("o hash fictício do login usa o mesmo custo dos hashes reais", () => {
  const { DUMMY_HASH } = require("../routes/login");
  const { BCRYPT_COST } = require("../helpers/users");
  expect(DUMMY_HASH).toMatch(new RegExp(`^\\$2b\\$${String(BCRYPT_COST).padStart(2, "0")}\\$`));
});
