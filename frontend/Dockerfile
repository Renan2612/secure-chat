# Build do frontend (B5), multi-estágio. Contexto: a RAIZ do repositório
# (o frontend importa ../shared/e2ee pelo alias do Vite).
#   1. node: npm ci (versões exatas do lockfile, só registry.npmjs.org) e build
#   2. caddy (a MESMA imagem do proxy, já fixada por digest): só o dist e o sh
#      para copiá-lo para o volume que o proxy monta SOMENTE LEITURA.
FROM node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json frontend/.npmrc ./
RUN npm ci --no-fund --no-audit
COPY shared/e2ee /app/shared/e2ee
COPY frontend/ ./
RUN npx vite build

FROM caddy:2.11.7-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f
COPY --from=build /app/frontend/dist /dist
# Ao subir, troca o conteúdo do volume pelo build desta imagem e sai.
CMD ["sh", "-c", "rm -rf /out/* && cp -R /dist/. /out/ && echo frontend publicado"]
