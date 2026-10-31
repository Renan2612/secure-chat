#!/usr/bin/env bash
# Clona (no SHA fixado) e sobe a stack do projeto ORIGINAL, propositalmente
# vulnerável, só para a comparação da Etapa 6. API em 127.0.0.1:18000; banco
# sem porta publicada. Idempotente: pode ser chamado antes de cada execução.
# A limpeza é feita por stop-original.sh (chamado pelo attack-matrix.sh).
set -uo pipefail
umask 077
cd "$(dirname "$0")/../.."

ORIG_REPO="https://github.com/asafebxd/MessageWebApp.git"
ORIG_SHA="873df2cd6c4749c0ebf9187079090b9cd84cd541"   # HEAD de main em 2026-10-31 (docs/09)
CLONE=".cache/MessageWebApp"
COMPOSE=(docker compose -f scripts/compare/original.compose.yml)

for tool in docker git node; do command -v "$tool" >/dev/null || { echo "erro: '$tool' não encontrado" >&2; exit 2; }; done

# Clone fixado no SHA (não vendorizado; .cache/ está no .gitignore).
if [ ! -d "$CLONE/.git" ]; then
  echo "clonando o original em $CLONE ..."
  git clone -q "$ORIG_REPO" "$CLONE" || { echo "erro: clone falhou (GitHub indisponível?)" >&2; exit 2; }
fi
git -C "$CLONE" fetch -q origin "$ORIG_SHA" 2>/dev/null || true
git -C "$CLONE" checkout -q "$ORIG_SHA" 2>/dev/null || { echo "erro: SHA $ORIG_SHA indisponível no clone" >&2; exit 2; }
echo "original fixado em $(git -C "$CLONE" rev-parse --short HEAD)"

# Segredos efêmeros (só em variáveis desta execução; nunca no git).
export ORIG_DB_PASSWORD="$(openssl rand -hex 16)"
export ORIG_SESSION_KEY="$(openssl rand -hex 16)"
# Guarda os segredos para o attack-matrix.sh reaproveitar a stack já de pé.
SECRETS="$(mktemp)"; chmod 600 "$SECRETS"
printf 'ORIG_DB_PASSWORD=%s\nORIG_SESSION_KEY=%s\n' "$ORIG_DB_PASSWORD" "$ORIG_SESSION_KEY" > "$SECRETS"
echo "$SECRETS" > .cache/orig-secrets-path

echo "construindo a imagem efêmera do original (deps em cache após a 1ª vez)..."
if ! timeout 175 "${COMPOSE[@]}" build api-orig >/dev/null 2>"$SECRETS.build"; then
  echo "erro: build da imagem do original falhou:" >&2; sed 's/^/  | /' "$SECRETS.build" >&2; exit 1
fi
rm -f "$SECRETS.build"

# O banco PRIMEIRO: o healthcheck da API consulta /rooms, que precisa do
# banco "messagewebapp" já criado.
if ! "${COMPOSE[@]}" up -d --wait --wait-timeout 60 db-orig >/dev/null 2>&1; then
  echo "erro: o Postgres do original não ficou saudável" >&2; exit 1
fi
# Aplica o schema do PRÓPRIO original (CREATE DATABASE messagewebapp + \c +
# tabelas), rodado como superusuário no banco default. Nada é alterado.
if ! "${COMPOSE[@]}" exec -T db-orig psql -v ON_ERROR_STOP=0 -U postgres -q < "$CLONE/database/migrations.sql" >/dev/null 2>&1; then
  echo "erro: não foi possível aplicar o esquema do original" >&2; exit 1
fi
echo "esquema do original aplicado (banco messagewebapp)"

echo "subindo a API do original..."
if ! "${COMPOSE[@]}" up -d --wait --wait-timeout 60 >/dev/null 2>&1; then
  echo "erro: a API do original não ficou saudável. Últimas linhas do log:" >&2
  "${COMPOSE[@]}" logs --tail 20 api-orig 2>&1 | sed 's/^/  | /' >&2
  exit 1
fi
echo "original no ar: API em http://127.0.0.1:18000 (banco sem porta no host)"
