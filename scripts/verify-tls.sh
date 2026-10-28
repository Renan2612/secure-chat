#!/usr/bin/env bash
# Provas da Etapa 4a contra a stack NO AR (docker compose --env-file
# backend/.env up --build). Termina com código != 0 se qualquer prova falhar.
#
# Uso: scripts/verify-tls.sh   (PUBLIC_HOST: ambiente, senão backend/.env, senão localhost)
#
# Cada prova exige evidência POSITIVA do comportamento esperado (ex.: o
# código de erro de certificado do curl, o alerta TLS do servidor): uma
# falha qualquer de rede não conta como "recusado".
#
# Cria um usuário e uma sala temporários (senha aleatória; nada de segredo
# na linha de comando: corpo e cookie vão por arquivos 0600) e os APAGA do
# banco na saída, inclusive em falha ou interrupção. Gasta 5 tentativas do
# limite de /register e /login por IP (20 a cada 15 min): rodar mais de 4
# vezes seguidas pode esbarrar no 429 (aguarde ou reinicie o backend).
set -uo pipefail
umask 077
cd "$(dirname "$0")/.."

COMPOSE=(docker compose --env-file backend/.env)
env_value() { sed -n "s/^$1=//p" backend/.env | tail -n 1; }
HOST="${PUBLIC_HOST:-$(env_value PUBLIC_HOST)}"; HOST="${HOST:-localhost}"
BASE="https://$HOST"
DB_USER="$(env_value DB_USER)"; DB_USER="${DB_USER:-postgres}"
DB_NAME="$(env_value DB_NAME)"; DB_NAME="${DB_NAME:-secure_chat}"

FAILS=0
ok() { printf '  OK     %s\n' "$*"; }
ko() { printf '  FALHA  %s\n' "$*"; FAILS=$((FAILS + 1)); }
# check "descrição" comando...  → OK se o comando terminar com sucesso.
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else ko "$desc"; fi; }
section() { printf '\n== %s\n' "$*"; }
has() { grep -qE -- "$1" <<<"$2"; }                     # has REGEX TEXTO
header_has() { [ -s "$2" ] && grep -qiE -- "$1" "$2"; }  # header_has REGEX ARQUIVO (arquivo precisa existir)

for tool in curl openssl node docker timeout grep sed awk; do
  command -v "$tool" >/dev/null || { echo "erro: '$tool' não encontrado" >&2; exit 2; }
done
if [ -z "$("${COMPOSE[@]}" ps -q --status running proxy 2>/dev/null)" ]; then
  echo "erro: a stack não está no ar (docker compose --env-file backend/.env up --build -d)" >&2
  exit 2
fi

TMP="$(mktemp -d)"
EMAIL="verify-tls-$(date +%s)-$RANDOM@example.invalid"
PASSWORD="$(openssl rand -hex 16)"
# Senha de cifragem do keystore do ws-client (Etapa 4b): outra, aleatória, só
# em variável; o keystore fica em $TMP e some na limpeza.
KEY_PASSPHRASE="$(openssl rand -hex 16)"
JAR="$TMP/cookies"

psql_dev() { "${COMPOSE[@]}" exec -T db psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -qAt "$@"; }

cleanup() {
  trap - EXIT INT TERM HUP
  # Remove tudo o que o script criou: mensagens, wraps e versões da chave da
  # sala, vínculos, salas, sessões, chaves públicas e o usuário.
  if ! psql_dev -v email="$EMAIL" >/dev/null 2>"$TMP/cleanup.err" <<'SQL'
WITH u AS (SELECT id FROM users WHERE email = :'email'),
     r AS (SELECT id AS room FROM rooms WHERE created_by IN (SELECT id FROM u)
           UNION SELECT room FROM rooms_users WHERE user_id IN (SELECT id FROM u)),
     w AS (DELETE FROM room_key_wraps WHERE room IN (SELECT room FROM r)
           OR recipient_id IN (SELECT id FROM u) OR sender_id IN (SELECT id FROM u)),
     m AS (DELETE FROM messages WHERE user_id IN (SELECT id FROM u) OR room IN (SELECT room FROM r)),
     ru AS (DELETE FROM rooms_users WHERE room IN (SELECT room FROM r) OR user_id IN (SELECT id FROM u)),
     s AS (DELETE FROM user_sessions WHERE (sess->>'userId')::int IN (SELECT id FROM u)),
     k AS (DELETE FROM user_keys WHERE user_id IN (SELECT id FROM u))
SELECT 1;
DELETE FROM room_key_versions WHERE room IN (SELECT id FROM rooms WHERE created_by IN (SELECT id FROM users WHERE email = :'email'));
DELETE FROM rooms WHERE created_by IN (SELECT id FROM users WHERE email = :'email');
DELETE FROM users WHERE email = :'email';
SQL
  then
    echo "aviso: a limpeza do banco falhou:" >&2
    sed 's/^/  | /' "$TMP/cleanup.err" >&2
  fi
  local left
  left="$(psql_dev -v email="$EMAIL" 2>/dev/null <<<"SELECT COUNT(*) FROM users WHERE email = :'email';" || echo "?")"
  if [ "$left" = "0" ]; then echo "(usuário temporário removido do banco)"; else echo "aviso: confira a remoção de $EMAIL do banco" >&2; fi
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP   # o EXIT acima roda a limpeza também em sinais

section "CA local do Caddy"
CA="$TMP/ca.crt"
if scripts/export-ca.sh "$CA" >/dev/null; then ok "CA raiz exportada (só o certificado; sem chave)"; else ko "exportar a CA"; exit 1; fi

section "Configuração do backend atrás do proxy"
backend_env() { "${COMPOSE[@]}" exec -T backend printenv "$1" 2>/dev/null | tr -d '\r'; }
check "TRUST_PROXY=1 (um salto exato: o Caddy)" test "$(backend_env TRUST_PROXY)" = "1"
check "NODE_ENV=production (cookie Secure)" test "$(backend_env NODE_ENV)" = "production"
check "CLIENT_URL=$BASE (origem única)" test "$(backend_env CLIENT_URL)" = "$BASE"

section "HTTP → HTTPS"
read -r code location < <(curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' "http://$HOST/")
check "http://$HOST/ → ${code:-?} ${location:-?} (esperado 308 para https://$HOST/)" test "${code:-} ${location:-}" = "308 https://$HOST/"

section "HTTPS, certificado e cabeçalhos"
status_of() { [ -s "$1" ] && awk 'NR==1{print $2}' "$1"; }
curl -s -D "$TMP/h_root" -o /dev/null --cacert "$CA" "$BASE/"
check "$BASE/ responde 200 com o certificado verificado pela CA local" test "$(status_of "$TMP/h_root")" = "200"
curl -s -D "$TMP/h_api" -o /dev/null --cacert "$CA" "$BASE/api/health"
check "$BASE/api/health responde 200 (prefixo /api removido pelo proxy)" test "$(status_of "$TMP/h_api")" = "200"
HSTS='^strict-transport-security: *max-age=(3[1-9][0-9]{6}|[4-9][0-9]{7}|[0-9]{9,}).*includesubdomains'
hsts_once() { [ "$(grep -ci '^strict-transport-security:' "$1")" = "1" ]; }
check "HSTS (max-age ≥ 1 ano, includeSubDomains) na página" header_has "$HSTS" "$TMP/h_root"
api_hsts() { header_has "$HSTS" "$TMP/h_api" && hsts_once "$TMP/h_api"; }
check "HSTS na API, exatamente um cabeçalho (sem duplicar com o backend)" api_hsts
no_server() { [ -s "$TMP/h_root" ] && [ -s "$TMP/h_api" ] && ! grep -qi '^server:' "$TMP/h_root" "$TMP/h_api"; }
check "sem cabeçalho Server" no_server
static_headers() { header_has "^content-security-policy: default-src 'none'" "$1" && header_has '^x-content-type-options: nosniff' "$1" && header_has '^referrer-policy:' "$1"; }
check "página estática com CSP, nosniff e Referrer-Policy" static_headers "$TMP/h_root"
curl -s -o /dev/null "$BASE/" 2>/dev/null; rc=$?
check "sem a CA local, o certificado é recusado (curl código $rc; esperado 60, falha de verificação)" test "$rc" = "60"

section "Cookie de sessão"
printf '{"email":"%s","password":"%s","name":"verify-tls"}' "$EMAIL" "$PASSWORD" >"$TMP/register.json"
printf '{"email":"%s","password":"%s"}' "$EMAIL" "$PASSWORD" >"$TMP/login.json"
reg=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" -H 'Content-Type: application/json' -d @"$TMP/register.json" "$BASE/api/register")
check "cadastro do usuário temporário (201)" test "$reg" = "201"
curl -s -D "$TMP/h_login" -o /dev/null -c "$JAR" --cacert "$CA" -H 'Content-Type: application/json' -d @"$TMP/login.json" "$BASE/api/login"
set_cookie="$(grep -i '^set-cookie: sid=' "$TMP/h_login" 2>/dev/null | tr -d '\r')"
check "login 200" test "$(status_of "$TMP/h_login")" = "200"
check "Set-Cookie sid com Secure"   has '; Secure' "$set_cookie"
check "Set-Cookie sid com HttpOnly" has '; HttpOnly' "$set_cookie"
check "Set-Cookie sid com SameSite" has '; SameSite=(Lax|Strict)' "$set_cookie"

section "Só o proxy é alcançável no host"
closed_port() { ! timeout 2 bash -c "</dev/tcp/127.0.0.1/$1" 2>/dev/null; }
for port in 8000 5432; do check "127.0.0.1:$port NÃO aceita conexão no host" closed_port "$port"; done
# PortBindings do contêiner ("{}" = nada publicado). `docker compose port`
# não serve: para porta não publicada ele devolve ":0" com código 0.
bindings() { local id; id="$("${COMPOSE[@]}" ps -q "$1")" && [ -n "$id" ] && docker inspect -f '{{json .HostConfig.PortBindings}}' "$id"; }
proxy_bindings_ok() { local b; b="$(bindings proxy)" && has '"443/tcp":\[\{"HostIp":"127\.0\.0\.1","HostPort":"443"\}\]' "$b" && ! has '"HostIp":"(0\.0\.0\.0|::|)"' "$b"; }
not_published() { [ "$(bindings "$1")" = "{}" ]; }
check "controle positivo: o proxy publica 443 (e 80) só em 127.0.0.1" proxy_bindings_ok
check "backend sem nenhuma porta publicada" not_published backend
check "db sem nenhuma porta publicada" not_published db

section "WebSocket"
upgrade() { # $1 = URL, $2 = Origin → imprime o status HTTP do pedido de upgrade
  curl -s -o /dev/null -w '%{http_code}' --http1.1 --max-time 3 --cacert "$CA" -b "$JAR" \
    -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H "Origin: $2" "$1"
}
c=$(upgrade "http://$HOST/ws" "$BASE");                    check "ws:// recusado (HTTP $c; esperado 308, sem 101)" test "$c" = "308"
c=$(upgrade "$BASE/ws" "https://site-malicioso.example");  check "wss:// com Origin de outro site recusado (HTTP $c; esperado 403)" test "$c" = "403"
c=$(upgrade "$BASE/ws" "$BASE");                           check "wss:// com a Origin certa aceita o upgrade (HTTP $c; controle positivo, esperado 101)" test "$c" = "101"
c=$(upgrade "$BASE/api/ws" "$BASE");                       check "/api/ws não é um segundo caminho para o WebSocket (HTTP $c; esperado 404)" test "$c" = "404"

# O ws-client (Etapa 4b) cria a sala temporária com a chave v1 e envia a
# mensagem CIFRADA por wss://.
CHAT_PASSWORD="$PASSWORD" CHAT_KEY_PASSPHRASE="$KEY_PASSPHRASE" timeout 30 node backend/tools/ws-client.js \
  --server "$BASE/api" --ca "$CA" --origin "$BASE" --email "$EMAIL" --keystore "$TMP/keystore.json" \
  --create-room "verify-tls" <<<"mensagem da verificação TLS" >"$TMP/client.out" 2>&1
client_status=$?
check "sala temporária criada pelo ws-client (com a chave da sala)" grep -q 'sala criada: id' "$TMP/client.out"
client_ok() { [ "$client_status" = 0 ] && grep -q 'enviada' "$TMP/client.out"; }
check "ws-client por wss:// com a CA: login, inscrição e envio cifrado confirmado (saída $client_status)" client_ok
[ "$client_status" = 0 ] || sed 's/^/         | /' "$TMP/client.out"

section "Versões e suítes TLS (openssl s_client)"
tls_try() { # $1 = versão (tls1_1|tls1_2|tls1_3), $2... = opções extras
  local v="$1"; shift
  echo | timeout 10 openssl s_client -connect "$HOST:443" -servername "$HOST" -CAfile "$CA" "-$v" "$@" 2>&1
}
# Recusa pelo SERVIDOR: houve conexão, o cliente ofereceu (SECLEVEL=0 libera
# o que o OpenSSL local bloquearia) e o servidor respondeu com alerta.
server_refused() { has '^CONNECTED\(' "$1" && has "$2" "$1" && has 'Cipher is \(NONE\)' "$1"; }
accepted() { has 'Verify return code: 0 \(ok\)' "$1" && ! has 'Cipher is \(NONE\)' "$1"; }
out=$(tls_try tls1_1 -cipher 'DEFAULT@SECLEVEL=0')
check "TLS 1.1 recusado pelo servidor (alerta protocol version)" server_refused "$out" 'alert protocol version'
for v in tls1_2 tls1_3; do
  out=$(tls_try "$v")
  proto=$(sed -n 's/^ *Protocol *: *//p' <<<"$out" | head -1)
  check "${v/tls1_/TLS 1.} aceito (${proto:-?}, certificado verificado)" accepted "$out"
done
out=$(tls_try tls1_2 -cipher 'ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-GCM-SHA256:@SECLEVEL=0')
check "TLS 1.2 só com suítes CBC ou sem ECDHE: o servidor recusa (alerta handshake failure)" server_refused "$out" 'alert handshake failure'

section "X-Forwarded-For forjado não muda o balde do rate limit"
probe() { # status e RateLimit-Remaining de um /register inválido (400, mas conta no limite)
  curl -s -o /dev/null -D - --cacert "$CA" -H "X-Forwarded-For: $1" -H 'Content-Type: application/json' -d '{}' "$BASE/api/register" \
    | tr -d '\r' | awk 'NR==1{s=$2} tolower($1)=="ratelimit-remaining:"{r=$2} END{print s, r}'
}
read -r s1 r1 < <(probe "1.2.3.4")
read -r s2 r2 < <(probe "203.0.113.77, 5.6.7.8")
echo "         X-Forwarded-For: 1.2.3.4 → HTTP ${s1:-?}, restam ${r1:-?}"
echo "         X-Forwarded-For: 203.0.113.77, 5.6.7.8 → HTTP ${s2:-?}, restam ${r2:-?}"
same_bucket() { [[ "${r1:-}" =~ ^[0-9]+$ && "${r2:-}" =~ ^[0-9]+$ ]] && [ "$((r1 - 1))" = "$r2" ]; }
if [ "${s1:-}" = "429" ] || [ "${s2:-}" = "429" ]; then
  ko "limite de /register esgotado (429): aguarde 15 min ou reinicie o backend e rode de novo"
else
  check "o segundo pedido gastou do MESMO balde (restam ${r1:-?} → ${r2:-?}): o proxy sobrescreve o cabeçalho" same_bucket
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "RESULTADO: todas as provas passaram"; else echo "RESULTADO: $FAILS prova(s) falharam"; fi
[ "$FAILS" -eq 0 ]
