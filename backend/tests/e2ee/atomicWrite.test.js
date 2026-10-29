// P2 (pendência da 4b-1): gravação atômica do keystore e do trust store.
// Arquivo temporário NO MESMO diretório, fsync do arquivo, rename por cima e
// fsync do diretório (sem o fsync, uma queda de energia logo depois do
// rename pode deixar o arquivo vazio ou com o conteúdo antigo), permissão
// 0600. Uma falha em qualquer passo deixa o arquivo anterior intacto e não
// deixa temporário para trás.
const fs = require("fs");
const os = require("os");
const path = require("path");
const store = require("../../../shared/e2ee/node");

const PASS = "senha-de-cifragem-atomica";

let dir;
let file;

beforeEach(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "sc-atomic-"));
  file = path.join(dir, "k.json");
  await store.writeSealedFile(file, PASS, { versao: "antiga" });
});
afterEach(() => jest.restoreAllMocks());

const leftovers = () => fs.readdirSync(dir).filter((name) => name !== "k.json");

test("grava com fsync do arquivo e do diretório, temporário no mesmo diretório, 0600", async () => {
  const fsyncs = [];
  const opened = new Map();
  const realOpen = fs.openSync;
  jest.spyOn(fs, "openSync").mockImplementation((p, ...rest) => {
    const fd = realOpen(p, ...rest);
    opened.set(fd, p);
    return fd;
  });
  const realFsync = fs.fsyncSync;
  jest.spyOn(fs, "fsyncSync").mockImplementation((fd) => {
    fsyncs.push(opened.get(fd));
    return realFsync(fd);
  });
  const renames = [];
  const realRename = fs.renameSync;
  jest.spyOn(fs, "renameSync").mockImplementation((from, to) => {
    renames.push([from, to, [...fsyncs]]);
    return realRename(from, to);
  });
  await store.writeSealedFile(file, PASS, { versao: "nova" });
  expect(renames).toHaveLength(1);
  const [tmp, target, syncedBefore] = renames[0];
  expect(path.dirname(tmp)).toBe(dir);
  expect(target).toBe(file);
  expect(syncedBefore).toEqual([tmp]); // o conteúdo está no disco ANTES do rename
  expect(fsyncs).toEqual([tmp, dir]); // e o diretório (a entrada nova) depois
  expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  expect(await store.readSealedFile(file, PASS)).toEqual({ versao: "nova" });
  expect(leftovers()).toEqual([]);
});

test.each([
  ["a escrita falha no meio (disco cheio)", "writeSync"],
  ["o fsync do arquivo falha", "fsyncSync"],
  ["o rename falha", "renameSync"],
])("falha no meio: %s → o arquivo anterior fica intacto e sem temporário", async (_label, fn) => {
  const real = fs[fn];
  jest.spyOn(fs, fn).mockImplementation((...args) => {
    if (fn === "writeSync") real(args[0], Buffer.from(String(args[1])).subarray(0, 10)); // grava um pedaço
    throw Object.assign(new Error("falha simulada"), { code: "ENOSPC" });
  });
  await expect(store.writeSealedFile(file, PASS, { versao: "nova" })).rejects.toThrow(/falha simulada/);
  jest.restoreAllMocks();
  expect(await store.readSealedFile(file, PASS)).toEqual({ versao: "antiga" });
  expect(leftovers()).toEqual([]);
});

test("falha só no fsync do diretório (depois do rename) é informada: o arquivo novo já está no lugar", async () => {
  const real = fs.fsyncSync;
  let calls = 0;
  jest.spyOn(fs, "fsyncSync").mockImplementation((fd) => {
    calls += 1;
    if (calls === 2) throw Object.assign(new Error("fsync do diretório falhou"), { code: "EIO" });
    return real(fd);
  });
  await expect(store.writeSealedFile(file, PASS, { versao: "nova" })).rejects.toThrow(/diretório/);
  jest.restoreAllMocks();
  expect(await store.readSealedFile(file, PASS)).toEqual({ versao: "nova" });
  expect(leftovers()).toEqual([]);
});
