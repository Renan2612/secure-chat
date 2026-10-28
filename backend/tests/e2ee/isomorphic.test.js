// O núcleo de shared/e2ee precisa rodar no navegador (D1): sem Buffer, sem
// módulos do Node e sem outra fonte de aleatoriedade além de getRandomValues.
// Só o adaptador (node.js) pode usar APIs do Node.
const fs = require("fs");
const path = require("path");

const dir = path.join(__dirname, "../../../shared/e2ee");
const coreFiles = fs.readdirSync(dir).filter((f) => f.endsWith(".js") && f !== "node.js");
const code = (file) => fs.readFileSync(path.join(dir, file), "utf8").replace(/\/\/.*$/gm, "");

test.each(coreFiles)("%s não usa Buffer, módulos do Node nem Math.random", (file) => {
  const source = code(file);
  expect(source).not.toMatch(/\bBuffer\b/);
  expect(source).not.toMatch(/require\(["'](node:)?(fs|crypto|path|os|util|child_process)["']\)/);
  expect(source).not.toMatch(/\bprocess\./);
  expect(source).not.toMatch(/Math\.random/);
  // Só requires relativos ao próprio módulo.
  for (const [, dep] of source.matchAll(/require\(["']([^"']+)["']\)/g)) expect(dep).toMatch(/^\.\//);
});

test("todo aleatório passa por crypto.getRandomValues, numa única função (primitives.randomBytes)", () => {
  const uses = coreFiles.flatMap((f) => (code(f).match(/getRandomValues/g) ?? []).map(() => f));
  expect(uses).toEqual(["primitives.js"]);
});
