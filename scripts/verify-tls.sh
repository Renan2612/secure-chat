#!/usr/bin/env bash
# Provas da Etapa 4a contra a stack NO AR (docker compose --env-file
# backend/.env up --build). Termina com código != 0 se qualquer prova falhar.
#
# Uso: scripts/verify-tls.sh        (PUBLIC_HOST padrão: localhost)
#
# Cria um usuário e uma sala temporários (senha aleatória, passada ao
# cliente só por variável de ambiente) e os APAGA do banco na saída, mesmo
# em caso de falha. Gasta 5 tentativas do limite de /register e /login por
# IP (20 a cada 15 min): rodar mais de 4 vezes seguidas pode esbarrar no 429
# (aguarde ou reinicie o backend).
set -uo pipefail
cd "$(dirname "$0")/.."

HOST="${PUBLIC_HOST:-localhost}"
BASE="https://$HOST"
COMPOSE=(docker compose --env-file backend/.env)
env_value() { sed -n "s/^$1=//p" backend/.env | tail -n 1; }
DB_USER="$(env_value DB_USER)"; DB_USER="${DB_USER:-postgres}"
DB_NAME="$(env_value DB_NAME)"; DB_NAME="${DB_NAME:-secure_chat}"

FAILS=0
ok() { printf '  OK     %s\n' "$*"; }
ko() { printf '  FALHA  %s\n' "$*"; FAILS=$((FAILS + 1)); }
# check "descrição" comando...  → OK se o comando terminar com sucesso.
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else ko "$desc"; fi; }
section() { printf '\n== %s\n' "$*"; }

for tool in curl openssl node docker; do
  command -v "$tool" >/dev/null || { echo "erro: '$tool' não encontrado" >&2; exit 2; }
done
if [ -z "$("${COMPOSE[@]}" ps -q --status running proxy 2>/dev/null)" ]; then
  echo "erro: a stack não está no ar (docker compose --env-file backend/.env up --build -d)" >&2
  exit 2
fi

TMP="$(mktemp -d)"
EMAIL="verify-tls-$(date +%s)-$RANDOM@example.invalid"
PASSWORD="$(openssl rand -hex 16)"
ROOM_ID=""

psql_dev() { "${COMPOSE[@]}" exec -T db psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -qAt "$@"; }

cleanup() {
  # Remove tudo o que o script criou: mensagens, vínculos, sala, sessões e o usuário.
  psql_dev -v email="$EMAIL" >/dev/null 2>&1 <<'SQL'
WITH u AS (SELECT id FROM users WHERE email = :'email'),
     r AS (SELECT room FROM rooms_users WHERE user_id IN (SELECT id FROM u)),
     m AS (DELETE FROM messages WHERE user_id IN (SELECT id FROM u) OR room IN (SELECT room FROM r)),
     ru AS (DELETE FROM rooms_users WHERE room IN (SELECT room FROM r) OR user_id IN (SELECT id FROM u)),
     s AS (DELETE FROM user_sessions WHERE (sess->>'userId')::int IN (SELECT id FROM u))
SELECT 1;
DELETE FROM rooms WHERE id NOT IN (SELECT room FROM rooms_users) AND name = 'verify-tls';
DELETE FROM users WHERE email = :'email';
SQL
  local left
  left="$(psql_dev -v email="$EMAIL" 2>/dev/null <<<"SELECT COUNT(*) FROM users WHERE email = :'email';" || echo "?")"
  [ "$left" = "0" ] && echo "(usuário temporário removido do banco)" || echo "aviso: confira a remoção de $EMAIL do banco" >&2
  rm -rf "$TMP"
}
trap cleanup EXIT

section "CA local do Caddy"
CA="$TMP/ca.crt"
if scripts/export-ca.sh "$CA" >/dev/null; then ok "CA raiz exportada (só o certificado; sem chave)"; else ko "exportar a CA"; exit 1; fi

section "HTTP → HTTPS"
read -r code location < <(curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' "http://$HOST/")
check "http://$HOST/ → $code $location (esperado 308 para https://$HOST/)" test "$code $location" = "308 https://$HOST/"

section "HTTPS, certificado e cabeçalhos"
curl -s -D "$TMP/h_root" -o /dev/null --cacert "$CA" "$BASE/" ; code_root=$(awk 'NR==1{print $2}' "$TMP/h_root")
check "$BASE/ responde 200 com o certificado verificado pela CA local" test "$code_root" = "200"
curl -s -D "$TMP/h_api" -o /dev/null --cacert "$CA" "$BASE/api/health"; code_api=$(awk 'NR==1{print $2}' "$TMP/h_api")
check "$BASE/api/health responde 200 (prefixo /api removido pelo proxy)" test "$code_api" = "200"
hsts_ok() { grep -i '^strict-transport-security:' "$1" | grep -qiE 'max-age=(3[1-9][0-9]{6}|[4-9][0-9]{7}|[0-9]{9,}).*includesubdomains'; }
hsts_once() { [ "$(grep -ci '^strict-transport-security:' "$1")" = "1" ]; }
check "HSTS (max-age ≥ 1 ano, includeSubDomains) na página" hsts_ok "$TMP/h_root"
check "HSTS na API, exatamente um cabeçalho (sem duplicar com o backend)" bash -c "$(declare -f hsts_ok hsts_once); hsts_ok '$TMP/h_api' && hsts_once '$TMP/h_api'"
check "sem cabeçalho Server" bash -c "! grep -qi '^server:' '$TMP/h_root' '$TMP/h_api'"
check "página estática com CSP, nosniff e Referrer-Policy" bash -c "grep -qi '^content-security-policy: default-src .none.' '$TMP/h_root' && grep -qi '^x-content-type-options: nosniff' '$TMP/h_root' && grep -qi '^referrer-policy:' '$TMP/h_root'"
check "certificado de $HOST NÃO é aceito sem a CA local (sem atalho inseguro)" bash -c "! curl -s -o /dev/null '$BASE/' 2>/dev/null"

section "Cookie de sessão"
reg=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"name\":\"verify-tls\"}" "$BASE/api/register")
check "cadastro do usuário temporário (201)" test "$reg" = "201"
curl -s -D "$TMP/h_login" -o /dev/null -c "$TMP/cookies" --cacert "$CA" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" "$BASE/api/login"
set_cookie="$(grep -i '^set-cookie: sid=' "$TMP/h_login" | tr -d '\r')"
check "login 200" test "$(awk 'NR==1{print $2}' "$TMP/h_login")" = "200"
check "Set-Cookie sid com Secure"   bash -c "grep -q '; Secure' <<<'$set_cookie'"
check "Set-Cookie sid com HttpOnly" bash -c "grep -q '; HttpOnly' <<<'$set_cookie'"
check "Set-Cookie sid com SameSite" bash -c "grep -qE '; SameSite=(Lax|Strict)' <<<'$set_cookie'"
SID="$(sed -n 's/^set-cookie: \(sid=[^;]*\).*/\1/Ip' <<<"$set_cookie")"

section "Só o proxy é alcançável no host"
for port in 8000 5432; do
  check "127.0.0.1:$port NÃO aceita conexão no host" bash -c "! timeout 2 bash -c '</dev/tcp/127.0.0.1/$port' 2>/dev/null"
done
published="$("${COMPOSE[@]}" ps --format '{{.Service}}={{.Publishers}}' | tr '\n' ' ')"
check "backend e db sem portas publicadas (só o proxy)" bash -c "! grep -qE '(backend|db)=\[\{[^]]*[0-9]+' <<<'$published'"

section "WebSocket"
upgrade() { # $1 = URL, $2 = Origin → imprime o status HTTP do pedido de upgrade
  curl -s -o /dev/null -w '%{http_code}' --http1.1 --max-time 3 --cacert "$CA" -b "$SID" \
    -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H "Origin: $2" "$1"
}
c=$(upgrade "http://$HOST/ws" "$BASE");            check "ws:// recusado (HTTP $c; esperado 308, sem 101)" test "$c" = "308"
c=$(upgrade "$BASE/ws" "https://site-malicioso.example"); check "wss:// com Origin de outro site recusado (HTTP $c; esperado 403)" test "$c" = "403"
c=$(upgrade "$BASE/ws" "$BASE");                   check "wss:// com a Origin certa aceita o upgrade (HTTP $c; controle positivo, esperado 101)" test "$c" = "101"
c=$(upgrade "$BASE/api/ws" "$BASE");               check "/api/ws não é um segundo caminho para o WebSocket (HTTP $c; esperado 404)" test "$c" = "404"

ROOM_ID="$(curl -s --cacert "$CA" -b "$SID" -H 'Content-Type: application/json' -d '{"name":"verify-tls"}' "$BASE/api/createRoom" \
  | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{try{console.log(JSON.parse(d).id??"")}catch{console.log("")}})')"
check "sala temporária criada" test -n "$ROOM_ID"
CHAT_PASSWORD="$PASSWORD" timeout 20 node backend/tools/ws-client.js --server "$BASE/api" --ca "$CA" --origin "$BASE" \
  --email "$EMAIL" --room "${ROOM_ID:-0}" <<<"mensagem da verificação TLS" >"$TMP/client.out" 2>&1
client_status=$?
check "ws-client por wss:// com a CA: login, inscrição e envio confirmado (saída $client_status)" \
  bash -c "[ $client_status = 0 ] && grep -q 'enviada' '$TMP/client.out'"
[ "$client_status" = 0 ] || sed 's/^/         | /' "$TMP/client.out"

section "Versões e suítes TLS (openssl s_client)"
tls_try() { # $1 = versão (tls1_1|tls1_2|tls1_3), $2... = opções extras
  local v="$1"; shift
  echo | timeout 10 openssl s_client -connect "$HOST:443" -servername "$HOST" -CAfile "$CA" "-$v" "$@" 2>&1
}
# SECLEVEL=0 libera o TLS 1.1 do lado do CLIENTE: a recusa tem de vir do servidor.
out=$(tls_try tls1_1 -cipher 'DEFAULT@SECLEVEL=0')
check "TLS 1.1 recusado pelo servidor (alerta protocol version)" bash -c "grep -q 'alert protocol version' <<<\"\$1\" && grep -q 'Cipher is (NONE)' <<<\"\$1\"" _ "$out"
for v in tls1_2 tls1_3; do
  out=$(tls_try "$v")
  proto=$(sed -n 's/^ *Protocol *: *//p' <<<"$out" | head -1)
  check "${v/tls1_/TLS 1.} aceito ($proto, certificado verificado)" bash -c "grep -q 'Verify return code: 0 (ok)' <<<\"\$1\" && ! grep -q 'Cipher is (NONE)' <<<\"\$1\"" _ "$out"
done
out=$(tls_try tls1_2 -cipher 'ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-GCM-SHA256')
check "TLS 1.2 com suíte CBC ou sem ECDHE recusado" bash -c "! grep -qE 'Cipher is [A-Z0-9]' <<<\"\$1\" || grep -q 'Cipher is (NONE)' <<<\"\$1\"" _ "$out"

section "X-Forwarded-For forjado não muda o balde do rate limit"
probe() { # status e RateLimit-Remaining de um /register inválido (400, mas conta no limite)
  curl -s -o /dev/null -D - --cacert "$CA" -H "X-Forwarded-For: $1" -H 'Content-Type: application/json' -d '{}' "$BASE/api/register" \
    | tr -d '\r' | awk 'NR==1{s=$2} tolower($1)=="ratelimit-remaining:"{r=$2} END{print s, r}'
}
read -r s1 r1 < <(probe "1.2.3.4")
read -r s2 r2 < <(probe "203.0.113.77, 5.6.7.8")
echo "         X-Forwarded-For: 1.2.3.4 → HTTP $s1, restam $r1"
echo "         X-Forwarded-For: 203.0.113.77, 5.6.7.8 → HTTP $s2, restam $r2"
if [ "$s1" = "429" ] || [ "$s2" = "429" ]; then
  ko "limite de /register esgotado (429): aguarde 15 min ou reinicie o backend e rode de novo"
else
  check "o segundo pedido gastou do MESMO balde (restam $r1 → $r2): o proxy sobrescreve o cabeçalho" test "$((r1 - 1))" = "${r2:-x}"
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "RESULTADO: todas as provas passaram"; else echo "RESULTADO: $FAILS prova(s) falharam"; fi
[ "$FAILS" -eq 0 ]
