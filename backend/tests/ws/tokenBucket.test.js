// Balde de fichas (realtime/tokenBucket.js) e a limpeza dos baldes de IP.
const { TokenBucket } = require("../../realtime/tokenBucket");
const { ConnectionRegistry } = require("../../realtime/registry");

let now;
beforeEach(() => {
  now = 1_000_000;
  jest.spyOn(Date, "now").mockImplementation(() => now);
});
afterEach(() => jest.restoreAllMocks());

test("gasta até a rajada e então recusa", () => {
  const bucket = new TokenBucket(3, 1);
  expect([bucket.take(), bucket.take(), bucket.take(), bucket.take()]).toEqual([true, true, true, false]);
});

test("repõe no ritmo configurado e não passa da rajada", () => {
  const bucket = new TokenBucket(2, 2); // 2 fichas/s
  bucket.take();
  bucket.take();
  now += 500; // +1 ficha
  expect(bucket.take()).toBe(true);
  expect(bucket.take()).toBe(false);
  now += 60_000; // muito tempo: no máximo a rajada
  expect(bucket.isFull()).toBe(true);
  expect([bucket.take(), bucket.take(), bucket.take()]).toEqual([true, true, false]);
});

test.each([
  ["rajada NaN", NaN, 1],
  ["rajada zero", 0, 1],
  ["reposição negativa", 5, -1],
  ["reposição infinita", 5, Infinity],
])("parâmetro inválido (%s) → erro em vez de limite que nunca recusa", (_l, burst, refill) => {
  expect(() => new TokenBucket(burst, refill)).toThrow(/TokenBucket/);
});

test("relógio que volta não gera fichas negativas nem extras", () => {
  const bucket = new TokenBucket(1, 1);
  bucket.take();
  now -= 10_000;
  expect(bucket.take()).toBe(false);
  now += 10_000 + 1000;
  expect(bucket.take()).toBe(true);
});

test("a limpeza esquece só os baldes de IP cheios (o mapa não cresce sem limite)", () => {
  const registry = new ConnectionRegistry();
  registry.takeUpgradeToken("10.0.0.1", 2, 1);
  registry.takeUpgradeToken("10.0.0.2", 2, 1);
  now += 5000; // os dois enchem de novo
  registry.takeUpgradeToken("10.0.0.3", 2, 1); // este está pela metade
  registry.sweepUpgradeBuckets();
  expect([...registry.upgradeBuckets.keys()]).toEqual(["10.0.0.3"]);
});
