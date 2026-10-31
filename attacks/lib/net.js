// HTTP(S) mínimo para os ataques: timeout SEMPRE (o original tem rotas que
// nunca respondem — ex.: POST /register), cofre de cookies simples, e CA
// local opcional (a stack final usa o certificado da CA do Caddy; a
// verificação NUNCA é desligada). Sem dependências além do Node.
import http from "node:http";
import https from "node:https";
import { readFileSync } from "node:fs";

export class Jar {
  constructor() { this.cookies = new Map(); }
  store(setCookie = []) {
    for (const line of setCookie) {
      const [pair] = line.split(";");
      const i = pair.indexOf("=");
      if (i > 0) this.cookies.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
    }
  }
  header() { return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "); }
}

export const request = (method, url, { headers = {}, body, caPath, timeoutMs = 5000, jar } = {}) =>
  new Promise((resolve) => {
    const u = new URL(url);
    const mod = u.protocol === "https:" ? https : http;
    const opts = { method, headers: { ...headers } };
    if (caPath) opts.ca = readFileSync(caPath);
    if (body !== undefined && !opts.headers["Content-Type"]) opts.headers["Content-Type"] = "application/json";
    if (jar && jar.header()) opts.headers.Cookie = jar.header();
    let payload;
    if (body === undefined) payload = undefined;
    else if (typeof body === "string") payload = body;
    else payload = JSON.stringify(body);
    if (payload !== undefined) opts.headers["Content-Length"] = Buffer.byteLength(payload);
    const req = mod.request(u, opts, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        if (jar) jar.store(res.headers["set-cookie"] ?? []);
        resolve({ status: res.statusCode, headers: res.headers, setCookies: res.headers["set-cookie"] ?? [], body: data });
      });
    });
    req.on("error", (err) => resolve({ error: err.code || err.message, status: 0, headers: {}, setCookies: [], body: "" }));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve({ error: "TIMEOUT", status: 0, headers: {}, setCookies: [], body: "" }); });
    if (payload !== undefined) req.write(payload);
    req.end();
  });

// JSON ou null (sem lançar).
export const asJson = (res) => { try { return JSON.parse(res.body); } catch { return null; } };
