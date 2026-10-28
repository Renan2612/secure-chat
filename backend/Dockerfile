FROM node:24-alpine

WORKDIR /app

# npm ci: instala exatamente o package-lock.json (falha se divergir do
# package.json), sem dependências de desenvolvimento.
COPY --chown=node:node package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=node:node . .

# Sem root dentro do container: um RCE no app não vira root na imagem.
USER node

EXPOSE 8000

# /health também consulta o banco (503 se ele estiver fora). Usa o fetch do
# próprio Node, sem depender de curl/wget na imagem.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch(`http://127.0.0.1:${process.env.SERVER_PORT || 8000}/health`).then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]

CMD ["node", "server.js"]
