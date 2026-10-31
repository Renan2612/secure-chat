// Monta evidencias/etapa6/matriz.{json,md} a partir das linhas JSONL
// (uma por ataque×alvo) e decide o código de saída: 1 se QUALQUER defesa da
// versão FINAL foi provada quebrada (observado "vulneravel"); 0 caso
// contrário. "inconclusivo" na final vira AVISO, não falha (limite de
// ambiente, ex.: dumpcap sem loopback). Nenhuma senha/cookie/chave entra
// aqui: os detalhes são contagens e nomes de marcadores descartáveis.
import { readFileSync, writeFileSync } from "node:fs";

const [rowsPath, jsonOut, mdOut, mutation = ""] = process.argv.slice(2);
const rows = readFileSync(rowsPath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));

const ids = [...new Set(rows.map((r) => String(r.id)))].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
const by = (id, alvo) => rows.find((r) => String(r.id) === id && r.alvo === alvo);

const icon = (r) => (!r ? "—" : r.observado === "inconclusivo" ? "？" : r.ok ? "✓" : "✗");
const esc = (s) => String(s ?? "").replace(/\|/g, "\\|");

let md = `# Matriz de ataques "antes e depois" — Etapa 6\n\n`;
md += `Gerado em ${new Date().toISOString()}${mutation ? ` · MUTAÇÃO: ${mutation}` : ""}.\n\n`;
md += `Original = \`asafebxd/MessageWebApp\` (propositalmente vulnerável, só em 127.0.0.1:18000). `;
md += `Final = a stack deste projeto (\`https://localhost\`). "esperado" é o que cada versão deveria fazer; `;
md += `"obs." é o que o ataque observou. ✓ = bate; ✗ = defesa quebrada; ？ = inconclusivo (limite de ambiente).\n\n`;
md += `| # | Ataque | Original (esp./obs.) | Final (esp./obs.) | Controle positivo |\n`;
md += `|---|---|---|---|---|\n`;
for (const id of ids) {
  const o = by(id, "original");
  const f = by(id, "final");
  const titulo = esc((o || f).titulo);
  const oc = o ? `${o.esperado}/${o.observado} ${icon(o)}` : "—";
  const fc = f ? `${f.esperado}/${f.observado} ${icon(f)}` : "—";
  md += `| ${id} | ${titulo} | ${oc} | ${fc} | ${esc((f || o).controle)} |\n`;
}

const finalRows = rows.filter((r) => r.alvo === "final");
const broken = finalRows.filter((r) => r.observado === "vulneravel");
const incon = finalRows.filter((r) => r.observado === "inconclusivo");
const origNotVuln = rows.filter((r) => r.alvo === "original" && r.observado !== "vulneravel");

md += `\n## Resumo\n\n`;
md += `- Final: ${finalRows.length - broken.length - incon.length}/${finalRows.length} defesas confirmadas`;
md += `${broken.length ? `, **${broken.length} QUEBRADA(S)**` : ""}${incon.length ? `, ${incon.length} inconclusiva(s)` : ""}.\n`;
if (broken.length) md += `- Quebradas: ${broken.map((r) => `#${r.id} (${r.detalhe})`).join("; ")}.\n`;
if (incon.length) md += `- Inconclusivas (limite de ambiente, não falham a matriz): ${incon.map((r) => `#${r.id}`).join(", ")}.\n`;
if (origNotVuln.length) md += `- Original NÃO vulnerável em (reportado com honestidade): ${origNotVuln.map((r) => `#${r.id} [${r.observado}]`).join(", ")}.\n`;
md += `\nDetalhes por linha em \`matriz.json\`.\n`;

writeFileSync(jsonOut, JSON.stringify({ geradoEm: new Date().toISOString(), mutacao: mutation || null, resultados: rows }, null, 2) + "\n");
writeFileSync(mdOut, md);

if (broken.length) {
  process.stderr.write(`FALHA: ${broken.length} defesa(s) da versão final quebrada(s).\n`);
  process.exit(1);
}
process.exit(0);
