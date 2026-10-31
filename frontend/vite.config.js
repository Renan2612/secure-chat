// Vite (B-D1/B-D2). O núcleo E2EE entra pelo alias @e2ee → ../shared/e2ee,
// SEM cópia: o mesmo código do backend e do ws-client. O build não gera
// nada inline (CSP: script-src 'self', style-src 'self').
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const e2eeDir = fileURLToPath(new URL("../shared/e2ee", import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@e2ee": e2eeDir } },
  server: { fs: { allow: [".", e2eeDir] } },
  build: {
    // Sem polyfill de modulepreload e sem assets embutidos como data: URI.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  test: { environment: "node", include: ["tests/**/*.test.js"] },
});
