// Política das flags SÓ DE TESTE (Etapa 6): honradas apenas em NODE_ENV=test
// e proibidas de subir em produção. Teste puro (sem banco).
const { TEST_FLAGS, flagsSet, honored, assertSafe } = require("../config/testFlags");
const { createApp } = require("../app");

const base = { NODE_ENV: "production", TRUST_PROXY: "1", SESSION_SECRET: "x".repeat(40) };

describe("assertSafe (recusa subir em produção com flag de teste)", () => {
  test("produção + cada flag de teste definida → lança nomeando a flag", () => {
    for (const flag of TEST_FLAGS) {
      const env = { ...base, [flag]: "inseguro-so-para-teste" };
      expect(() => assertSafe(env)).toThrow(new RegExp(flag));
    }
  });

  test("produção + flag com valor QUALQUER (até errado) → ainda recusa (falha fechada)", () => {
    expect(() => assertSafe({ ...base, TEST_SKIP_ROOM_MEMBER: "1" })).toThrow(/produç|production/i);
  });

  test("produção sem nenhuma flag → não lança", () => {
    expect(() => assertSafe({ ...base })).not.toThrow();
  });

  test("test e dev com flag definida → não lança (só não é produção)", () => {
    expect(() => assertSafe({ NODE_ENV: "test", E2EE_TEST_CLOCK: "inseguro-so-para-teste" })).not.toThrow();
    expect(() => assertSafe({ NODE_ENV: undefined, E2EE_TEST_SKIP_PURGE: "inseguro-so-para-teste" })).not.toThrow();
  });

  test("flagsSet lista só as definidas e não-vazias", () => {
    expect(flagsSet({ TEST_SKIP_ROOM_MEMBER: "x", E2EE_TEST_CLOCK: "" })).toEqual(["TEST_SKIP_ROOM_MEMBER"]);
  });
});

describe("honored (flag só tem efeito em NODE_ENV=test e com o valor exato)", () => {
  test("test + valor exato → true", () => {
    expect(honored("TEST_SKIP_ROOM_MEMBER", "vx", { NODE_ENV: "test", TEST_SKIP_ROOM_MEMBER: "vx" })).toBe(true);
  });
  test("produção + valor exato → false (ignorada)", () => {
    expect(honored("TEST_SKIP_ROOM_MEMBER", "vx", { NODE_ENV: "production", TEST_SKIP_ROOM_MEMBER: "vx" })).toBe(false);
  });
  test("test + valor errado → false", () => {
    expect(honored("TEST_SKIP_ROOM_MEMBER", "vx", { NODE_ENV: "test", TEST_SKIP_ROOM_MEMBER: "outro" })).toBe(false);
  });
});

describe("createApp recusa boot em produção com flag de teste", () => {
  const saved = { ...process.env };
  afterEach(() => {
    process.env.NODE_ENV = saved.NODE_ENV;
    delete process.env.TEST_SKIP_ROOM_MEMBER;
  });
  test("NODE_ENV=production + TEST_SKIP_ROOM_MEMBER → createApp lança", () => {
    process.env.NODE_ENV = "production";
    process.env.TEST_SKIP_ROOM_MEMBER = "inseguro-so-para-teste";
    expect(() => createApp()).toThrow(/flag\(s\) de teste|TEST_SKIP_ROOM_MEMBER/);
  });
  test("NODE_ENV=test + TEST_SKIP_ROOM_MEMBER → createApp sobe", () => {
    process.env.NODE_ENV = "test";
    process.env.TEST_SKIP_ROOM_MEMBER = "inseguro-so-para-teste";
    expect(() => createApp()).not.toThrow();
  });
});
