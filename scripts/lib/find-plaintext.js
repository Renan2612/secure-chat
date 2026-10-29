#!/usr/bin/env node
// Uso: node scripts/lib/find-plaintext.js MARCADOR < entrada
// Procura o marcador como um observador faria: em claro, em hexadecimal e
// DENTRO de qualquer trecho base64/base64url decodificado (ex.: o "ct" de um
// envelope que não foi cifrado de verdade). A entrada pode ser binária
// (captura) ou texto (despejo do banco, saída do tshark).
// Sai 0 e diz onde achou; 10 se NÃO achou; qualquer outra coisa (2 = erro de
// uso ou exceção) é falha do detector — o chamador NÃO pode tratá-la como
// "não achou" (seria um OK falso).
process.on("uncaughtException", (err) => {
  process.stderr.write(`find-plaintext: ${err.message}\n`);
  process.exit(2);
});
const marker = process.argv[2];
if (!marker) {
  process.stderr.write("uso: find-plaintext.js MARCADOR < entrada\n");
  process.exit(2);
}
const needle = Buffer.from(marker, "utf8");

const chunks = [];
process.stdin.on("data", (c) => chunks.push(c));
process.stdin.on("end", () => {
  const input = Buffer.concat(chunks);
  if (input.includes(needle)) return found("em claro");
  const text = input.toString("latin1");
  if (text.toLowerCase().includes(needle.toString("hex"))) return found("em hexadecimal");
  for (const token of text.match(/[A-Za-z0-9+/_-]{8,}={0,2}/g) ?? []) {
    const decoded = Buffer.from(token.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    if (decoded.includes(needle)) return found(`dentro de um trecho base64 decodificado (${token.slice(0, 24)}…)`);
  }
  process.exit(10);
});

function found(where) {
  process.stdout.write(`${where}\n`);
  process.exit(0);
}
