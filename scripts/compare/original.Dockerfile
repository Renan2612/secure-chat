# Imagem EFÊMERA (local, nunca enviada nem commitada) do backend do projeto
# original, só para a comparação da Etapa 6. Contexto de build: o clone em
# .cache/MessageWebApp (SHA fixado em docs/09). O código do original não é
# alterado — só copiado. As deps antigas ficam numa camada em cache, então
# as reexecuções são rápidas. O frontend do original não é necessário.
FROM node:16-bullseye-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install --no-audit --no-fund --loglevel=error
COPY server.js ./
COPY routes ./routes
COPY helpers ./helpers
COPY database ./database
CMD ["node", "server.js"]
