const { pool, resetDb, createUser } = require("./helpers");

beforeEach(resetDb);
afterAll(() => pool.end());

test("infra de teste: cadastro e login de um usuário funcionam", async () => {
  const user = await createUser("alice");
  expect(user.id).toEqual(expect.any(Number));
});
