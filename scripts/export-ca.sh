#!/usr/bin/env bash
# Exporta o certificado RAIZ (público) da CA local do Caddy, para clientes
# confiarem em https://localhost no desenvolvimento (curl --cacert,
# ws-client --ca, NODE_EXTRA_CA_CERTS, importação no navegador).
#
# Uso (com a stack no ar):  scripts/export-ca.sh [arquivo-de-saída]
#   padrão: certs/caddy-local-root.crt (certs/ está no .gitignore)
#
# NUNCA exporta root.key nem intermediate.key: a chave privada da CA fica
# só no volume caddy_data. Quem tiver essa chave emite certificados aceitos
# por todo cliente que confia nesta CA.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-certs/caddy-local-root.crt}"
SRC=/data/caddy/pki/authorities/local/root.crt
mkdir -p "$(dirname "$OUT")"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

docker compose --env-file backend/.env exec -T proxy cat "$SRC" >"$TMP"

# Trava: o arquivo deve ser exatamente um certificado, sem nenhuma chave.
if grep -q "PRIVATE KEY" "$TMP"; then
  echo "erro: o arquivo exportado contém uma chave privada; abortado" >&2
  exit 1
fi
openssl x509 -in "$TMP" -noout 2>/dev/null || { echo "erro: $SRC não é um certificado X.509" >&2; exit 1; }

install -m 0644 "$TMP" "$OUT"
echo "CA exportada para $OUT"
openssl x509 -in "$OUT" -noout -subject -enddate
openssl x509 -in "$OUT" -noout -fingerprint -sha256
cat <<MSG
Use com:
  curl --cacert $OUT https://localhost/
  node backend/tools/ws-client.js --server https://localhost/api --ca $OUT ...
  NODE_EXTRA_CA_CERTS=$OUT node ...
MSG
