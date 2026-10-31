// Teste de ponta a ponta com navegador REAL (C5) contra a stack no ar
// (docker compose --env-file backend/.env up --build). Chromium headless do
// ~/.cache/ms-playwright (npx playwright install chromium, sem sudo).
// Certificado: NÃO desligamos a verificação; o Chromium aceita só a SPKI do
// intermediário da CA local do Caddy, depois de conferir com o OpenSSL que
// ele é assinado pela raiz exportada (scripts/export-ca.sh).
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defineConfig } from "@playwright/test";

const HOST = process.env.PUBLIC_HOST || "localhost";
const root = join(import.meta.dirname, "..");

const pinnedSpki = () => {
  const dir = mkdtempSync(join(tmpdir(), "e2e-ca-"));
  const ca = join(dir, "ca.crt");
  execFileSync(join(root, "scripts/export-ca.sh"), [ca], { stdio: "ignore" });
  const chain = execFileSync("openssl", ["s_client", "-connect", `${HOST}:443`, "-servername", HOST, "-showcerts"], { input: "", stdio: ["pipe", "pipe", "ignore"] }).toString();
  const certs = chain.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
  if (certs.length < 2) throw new Error("cadeia do servidor sem o intermediário");
  const inter = join(dir, "inter.pem");
  writeFileSync(inter, `${certs[1]}\n`);
  execFileSync("openssl", ["verify", "-CAfile", ca, inter], { stdio: "ignore" }); // lança se não for da nossa raiz
  const der = execFileSync("sh", ["-c", `openssl x509 -in "${inter}" -noout -pubkey | openssl pkey -pubin -outform DER`]);
  return execFileSync("openssl", ["dgst", "-sha256", "-binary"], { input: der }).toString("base64");
};

export default defineConfig({
  testDir: "e2e",
  timeout: 120000,
  workers: 1,
  reporter: "list",
  globalTeardown: "./e2e/teardown.js",
  use: {
    baseURL: `https://${HOST}`,
    launchOptions: { args: [`--ignore-certificate-errors-spki-list=${pinnedSpki()}`] },
  },
});
