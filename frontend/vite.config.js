import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const e2eeDir = fileURLToPath(new URL("../shared/e2ee", import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@e2ee": e2eeDir } },
  server: { fs: { allow: [".", e2eeDir] } },
  test: { environment: "node", include: ["tests/**/*.test.js"] },
});
