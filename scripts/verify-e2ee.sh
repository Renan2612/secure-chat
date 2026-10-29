#!/usr/bin/env bash
# Provas da Etapa 4b-1 (E2EE) contra a stack NO AR (docker compose --env-file
# backend/.env up --build). Termina com código != 0 se qualquer prova falhar.
#
# Uso: scripts/verify-e2ee.sh
#      MUTATION=plain-envelope scripts/verify-e2ee.sh   (deve FALHAR)
#      MUTATION=no-encrypt scripts/verify-e2ee.sh       (deve FALHAR)
#      KEEP_CAPTURE=capturas scripts/verify-e2ee.sh     (guarda a captura)
#
# Sem sudo: a captura usa o dumpcap como usuário do grupo wireshark.
# Cria dois usuários (@example.invalid, senhas aleatórias só em variáveis) e
# uma sala temporários; Alice e Bob (dois ws-client) trocam mensagens com
# marcadores únicos enquanto o tráfego proxy → backend (rede interna do
# Docker, porta 8000, em HTTP puro de propósito) é capturado. Prova:
#   (a) os marcadores NÃO aparecem em nenhuma coluna do banco nem na captura
#       da rede interna — nem em claro, nem dentro de base64 decodificado —
#       com controles positivos (a captura tem tráfego, o upgrade e o JSON do
#       protocolo aparecem em claro; o detector acha o marcador codificado);
#   (b) cada cliente decifrou a mensagem do outro;
#   (c) o banco só tem o envelope (estrutura E2EE v1, key_version 1).
# Tudo o que foi criado é APAGADO na saída (trap), inclusive em falha.
# Gasta 4 tentativas do limite de /register e /login por IP (20 / 15 min).
set -uo pipefail
umask 077
cd "$(dirname "$0")/.."

COMPOSE=(docker compose --env-file backend/.env)
env_value() { sed -n "s/^$1=//p" backend/.env | tail -n 1; }
HOST="${PUBLIC_HOST:-$(env_value PUBLIC_HOST)}"; HOST="${HOST:-localhost}"
BASE="https://$HOST"
DB_USER="$(env_value DB_USER)"; DB_USER="${DB_USER:-postgres}"
DB_NAME="$(env_value DB_NAME)"; DB_NAME="${DB_NAME:-secure_chat}"
MUTATION="${MUTATION:-}"

FAILS=0
ok() { printf '  OK     %s\n' "$*"; }
ko() { printf '  FALHA  %s\n' "$*"; FAILS=$((FAILS + 1)); }
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else ko "$desc"; fi; }
section() { printf '\n== %s\n' "$*"; }

for tool in curl openssl node docker dumpcap tshark timeout grep sed mkfifo; do
  command -v "$tool" >/dev/null || { echo "erro: '$tool' não encontrado" >&2; exit 2; }
done
case "$MUTATION" in "" | plain-envelope | no-encrypt) ;; *) echo "erro: MUTATION inválida: $MUTATION" >&2; exit 2 ;; esac
if [ -z "$("${COMPOSE[@]}" ps -q --status running proxy 2>/dev/null)" ]; then
  echo "erro: a stack não está no ar (docker compose --env-file backend/.env up --build -d)" >&2
  exit 2
fi
PROJECT="$("${COMPOSE[@]}" ps --format '{{.Project}}' 2>/dev/null | head -n 1)"
NET_ID="$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT" --filter label=com.docker.compose.network=interna | head -n 1)"
[ -n "$NET_ID" ] || { echo "erro: rede 'interna' do projeto $PROJECT não encontrada" >&2; exit 2; }
BRIDGE="br-$(docker network inspect -f '{{.Id}}' "$NET_ID" | cut -c1-12)"
dumpcap -D 2>/dev/null | grep -qw "$BRIDGE" || { echo "erro: o dumpcap não enxerga $BRIDGE (grupo wireshark ativo nesta sessão?)" >&2; exit 2; }

TMP="$(mktemp -d)"
STAMP="$(date +%s)-$RANDOM"
ROOM_NAME="verify-e2ee-$STAMP"
A_EMAIL="verify-e2ee-$STAMP-a@example.invalid"
B_EMAIL="verify-e2ee-$STAMP-b@example.invalid"
A_PASSWORD="$(openssl rand -hex 16)"; B_PASSWORD="$(openssl rand -hex 16)"
A_KEYPASS="$(openssl rand -hex 16)"; B_KEYPASS="$(openssl rand -hex 16)"
MARK_A="MARCADOR-ALICE-$(openssl rand -hex 8)"
MARK_B="MARCADOR-BOB-$(openssl rand -hex 8)"
CAPTURE="$TMP/interna.pcapng"
PIDS=()

psql_dev() { "${COMPOSE[@]}" exec -T db psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -qAt "$@"; }

cleanup() {
  local rc=$?
  trap - EXIT INT TERM HUP PIPE
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
  if ! psql_dev -v a="$A_EMAIL" -v b="$B_EMAIL" >/dev/null 2>"$TMP/cleanup.err" <<'SQL'
WITH u AS (SELECT id FROM users WHERE email IN (:'a', :'b')),
     r AS (SELECT id AS room FROM rooms WHERE created_by IN (SELECT id FROM u)
           UNION SELECT room FROM rooms_users WHERE user_id IN (SELECT id FROM u)),
     w AS (DELETE FROM room_key_wraps WHERE room IN (SELECT room FROM r)
           OR recipient_id IN (SELECT id FROM u) OR sender_id IN (SELECT id FROM u)),
     m AS (DELETE FROM messages WHERE user_id IN (SELECT id FROM u) OR room IN (SELECT room FROM r)),
     ru AS (DELETE FROM rooms_users WHERE room IN (SELECT room FROM r) OR user_id IN (SELECT id FROM u)),
     s AS (DELETE FROM user_sessions WHERE (sess->>'userId')::int IN (SELECT id FROM u)),
     k AS (DELETE FROM user_keys WHERE user_id IN (SELECT id FROM u))
SELECT 1;
DELETE FROM room_key_versions WHERE room IN (SELECT id FROM rooms WHERE created_by IN (SELECT id FROM users WHERE email IN (:'a', :'b')));
DELETE FROM rooms WHERE created_by IN (SELECT id FROM users WHERE email IN (:'a', :'b'));
DELETE FROM users WHERE email IN (:'a', :'b');
SQL
  then
    echo "ERRO: a limpeza do banco falhou:" >&2
    sed 's/^/  | /' "$TMP/cleanup.err" >&2
    rc=3
  fi
  local left
  left="$(psql_dev -v a="$A_EMAIL" -v b="$B_EMAIL" 2>/dev/null <<<"SELECT COUNT(*) FROM users WHERE email IN (:'a', :'b');" || echo "?")"
  if [ "$left" = "0" ]; then
    echo "(usuários, sala e mensagens temporários removidos do banco)"
  else
    echo "ERRO: usuários temporários ainda no banco ($A_EMAIL, $B_EMAIL)" >&2
    rc=3
  fi
  if [ -n "${KEEP_CAPTURE:-}" ] && [ -s "$CAPTURE" ]; then
    local kept="$KEEP_CAPTURE/verify-e2ee-$STAMP${MUTATION:+-$MUTATION}.pcapng"
    if mkdir -p "$KEEP_CAPTURE" && cp "$CAPTURE" "$kept"; then echo "(captura guardada em $kept)"; else echo "aviso: não foi possível guardar a captura em $KEEP_CAPTURE" >&2; fi
  fi
  rm -rf "$TMP" # keystores, trust stores, cookies e a captura
  exit "$rc"   # limpeza que falhou nunca termina com 0
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP   # o EXIT acima roda a limpeza também em sinais
trap 'exit 141' PIPE           # escrever para um cliente que já saiu: falha, com limpeza

# Espera uma linha casar com o regex no arquivo (até N segundos).
wait_for() { # wait_for ARQUIVO REGEX SEGUNDOS
  local i
  for ((i = 0; i < $3 * 5; i += 1)); do grep -qE -- "$2" "$1" 2>/dev/null && return 0; sleep 0.2; done
  return 1
}

# Asserção parametrizada: esperar-claro (o texto TEM de aparecer, controle
# positivo) ou esperar-cifrado (NÃO pode aparecer nem decodificado).
expect_text() { # expect_text esperar-claro|esperar-cifrado "descrição" TEXTO ARQUIVO...
  local mode="$1" desc="$2" needle="$3" where found file
  shift 3
  for file in "$@"; do
    [ -r "$file" ] || { ko "$desc — arquivo não legível: $file"; return; }
  done
  [ -n "$needle" ] || { ko "$desc — texto procurado vazio"; return; }
  where="$(cat "$@" | node scripts/lib/find-plaintext.js "$needle")"
  found=$?
  # 0 = achou, 10 = não achou; qualquer outro código é o DETECTOR que falhou
  # e nunca conta como "não achou".
  case "$found" in 0 | 10) ;; *) ko "$desc — o detector falhou (código $found)"; return ;; esac
  case "$mode" in
    esperar-claro) if [ "$found" = 0 ]; then ok "$desc (achado $where)"; else ko "$desc (NÃO achado)"; fi ;;
    esperar-cifrado) if [ "$found" = 10 ]; then ok "$desc"; else ko "$desc — ACHADO $where"; fi ;;
    *) echo "erro: modo $mode" >&2; exit 2 ;;
  esac
}

section "Preparação"
[ -n "$MUTATION" ] && echo "  (MUTAÇÃO ATIVA: $MUTATION — esperado: provas falharem)"
CA="$TMP/ca.crt"
if scripts/export-ca.sh "$CA" >/dev/null; then ok "CA raiz exportada"; else ko "exportar a CA"; exit 1; fi
register() { # register EMAIL SENHA NOME → HTTP status
  printf '{"email":"%s","password":"%s","name":"%s"}' "$1" "$2" "$3" >"$TMP/register.json"
  curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" -H 'Content-Type: application/json' -H "Origin: $BASE" \
    --data-binary "@$TMP/register.json" "$BASE/api/register"
}
check "usuária temporária Alice cadastrada" test "$(register "$A_EMAIL" "$A_PASSWORD" "Alice e2ee")" = "201"
check "usuário temporário Bob cadastrado" test "$(register "$B_EMAIL" "$B_PASSWORD" "Bob e2ee")" = "201"
rm -f "$TMP/register.json"

section "Captura da rede interna proxy → backend ($BRIDGE, tcp port 8000)"
dumpcap -q -i "$BRIDGE" -f "tcp port 8000" -a duration:120 -w "$CAPTURE" 2>"$TMP/dumpcap.err" &
DUMPCAP=$!
PIDS+=("$DUMPCAP")
wait_for "$TMP/dumpcap.err" "Capturing on" 10 || sleep 1

# Um ws-client com stdin num FIFO (as linhas são escritas pelo script).
start_client() { # start_client NOME EMAIL SENHA SENHA-CIFRAGEM ARGS...
  local name="$1" email="$2" password="$3" keypass="$4"
  shift 4
  mkfifo "$TMP/$name.in"
  local preload=()
  [ -n "$MUTATION" ] && preload=(--require "./scripts/mutations/$MUTATION.js")
  CHAT_PASSWORD="$password" CHAT_KEY_PASSPHRASE="$keypass" HOME="$TMP/home-$name" timeout 90 node "${preload[@]}" \
    backend/tools/ws-client.js --server "$BASE/api" --ca "$CA" --origin "$BASE" --email "$email" \
    --keystore "$TMP/home-$name/keystore.json" "$@" <"$TMP/$name.in" >"$TMP/$name.out" 2>&1 &
  PIDS+=($!)
  eval "${name}_PID=$!"
}

mkdir -p "$TMP/home-alice" "$TMP/home-bob"
start_client alice "$A_EMAIL" "$A_PASSWORD" "$A_KEYPASS" --create-room "$ROOM_NAME"
exec {ALICE_IN}>"$TMP/alice.in"
wait_for "$TMP/alice.out" "sala criada: id [0-9]+; convite" 30
read -r ROOM_ID INVITE < <(sed -nE 's/.*sala criada: id ([0-9]+); convite: ([0-9a-f]+).*/\1 \2/p' "$TMP/alice.out")
check "Alice criou a sala com a chave v1 (sala ${ROOM_ID:-?})" test -n "${ROOM_ID:-}"
A_ID="$(sed -nE 's/.*logado como .* \(usuário ([0-9]+)\).*/\1/p' "$TMP/alice.out")"

start_client bob "$B_EMAIL" "$B_PASSWORD" "$B_KEYPASS" --room "${ROOM_ID:-0}" --join "${INVITE:-x}"
exec {BOB_IN}>"$TMP/bob.in"
wait_for "$TMP/bob.out" "logado como" 30
B_ID="$(sed -nE 's/.*logado como .* \(usuário ([0-9]+)\).*/\1/p' "$TMP/bob.out")"
# Quem decide quem é membro é o servidor: o cliente da Alice só ANUNCIA o
# Bob, e a chave só é entregue com a aprovação explícita dela.
wait_for "$TMP/alice.out" "/approve ${B_ID:-x}" 30
announced_only() {
  [ -n "${B_ID:-}" ] && grep -qF "/approve $B_ID" "$TMP/alice.out" && ! grep -q 'chave da sala entregue' "$TMP/alice.out"
}
check "o cliente da Alice anunciou o Bob (usuário ${B_ID:-?}) sem lhe entregar a chave sozinho" announced_only
echo "/approve ${B_ID:-x}" >&"$ALICE_IN"
wait_for "$TMP/bob.out" "chave da sala [0-9]+ disponível" 30
check "Bob recebeu a chave da sala após o /approve da Alice" grep -q "chave da sala ${ROOM_ID:-x} disponível" "$TMP/bob.out"

echo "$MARK_A" >&"$ALICE_IN"
wait_for "$TMP/bob.out" "$MARK_A" 15
echo "$MARK_B" >&"$BOB_IN"
wait_for "$TMP/alice.out" "$MARK_B" 15
sleep 1
exec {ALICE_IN}>&- {BOB_IN}>&-   # fim da entrada: os clientes saem e fazem logout
wait "$alice_PID"; A_STATUS=$?
wait "$bob_PID"; B_STATUS=$?
kill -INT "$DUMPCAP" 2>/dev/null; wait "$DUMPCAP" 2>/dev/null
PACKETS="$(tshark -r "$CAPTURE" 2>/dev/null | wc -l)"
DROPPED="$(sed -nE 's#.*received/dropped on interface.*: [0-9]+/([0-9]+).*#\1#p' "$TMP/dumpcap.err" | head -n 1)"
tshark -r "$CAPTURE" -d tcp.port==8000,http -T fields -e text 2>/dev/null >"$TMP/capture.txt"

section "(b) cada cliente decifrou a mensagem do outro"
check "Bob mostra a mensagem da Alice decifrada e assinada por ela" grep -qF "usuário ${A_ID:-?} [não verificado]: $MARK_A" "$TMP/bob.out"
check "Alice mostra a mensagem do Bob decifrada e assinada por ele" grep -qF "usuário ${B_ID:-?} [não verificado]: $MARK_B" "$TMP/alice.out"
check "os dois clientes terminaram sem erro (saídas $A_STATUS e $B_STATUS)" test "$A_STATUS:$B_STATUS" = "0:0"

section "(a) captura da rede interna (onde o TLS já terminou)"
check "controle positivo: a captura tem tráfego ($PACKETS pacotes)" test "$PACKETS" -gt 0
check "a captura não perdeu pacotes (descartados: ${DROPPED:-?})" test "${DROPPED:-x}" = "0"
expect_text esperar-claro "controle positivo: o upgrade do /ws aparece em claro" "Upgrade: websocket" "$CAPTURE" "$TMP/capture.txt"
expect_text esperar-claro "controle positivo: o JSON do protocolo aparece em claro (MSG_SEND)" '"type":"MSG_SEND"' "$TMP/capture.txt"
printf '%s' "$MARK_A" | node -e 'process.stdout.write(Buffer.from(require("fs").readFileSync(0)).toString("base64url"))' >"$TMP/selftest.txt"
expect_text esperar-claro "controle positivo do detector: acha o marcador codificado em base64url" "$MARK_A" "$TMP/selftest.txt"
expect_text esperar-cifrado "marcador da Alice não aparece na captura" "$MARK_A" "$CAPTURE" "$TMP/capture.txt"
expect_text esperar-cifrado "marcador do Bob não aparece na captura" "$MARK_B" "$CAPTURE" "$TMP/capture.txt"

section "(a) e (c) banco de dados"
: >"$TMP/db.txt"
TABLES="$(psql_dev -c "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1")"
check "lista de tabelas do banco obtida ($(wc -w <<<"$TABLES") tabelas)" test "$(wc -w <<<"$TABLES")" -ge 8
DUMP_FAILS=0
for table in $TABLES; do
  psql_dev -c "SELECT row_to_json(t)::text FROM \"$table\" t" >>"$TMP/db.txt" || { ko "despejo da tabela $table falhou"; DUMP_FAILS=1; }
done
check "todas as tabelas foram despejadas para a varredura" test "$DUMP_FAILS" = 0
expect_text esperar-claro "controle positivo: o nome da sala (metadado) aparece em claro no banco" "$ROOM_NAME" "$TMP/db.txt"
expect_text esperar-cifrado "marcador da Alice não aparece em nenhuma coluna" "$MARK_A" "$TMP/db.txt"
expect_text esperar-cifrado "marcador do Bob não aparece em nenhuma coluna" "$MARK_B" "$TMP/db.txt"
psql_dev -c "SELECT message FROM messages WHERE room = ${ROOM_ID:-0} ORDER BY id" >"$TMP/bodies.txt"
# Controle positivo amarrado a ESTA execução: o texto cifrado exato que o
# banco guardou precisa aparecer no despejo e na captura (prova que as
# mensagens com os marcadores foram mesmo varridas).
CT_A="$(head -n 1 "$TMP/bodies.txt" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{try{process.stdout.write(JSON.parse(d).ct.slice(0,40))}catch{}})')"
expect_text esperar-claro "controle positivo: o ct da 1ª mensagem desta execução está no despejo do banco" "$CT_A" "$TMP/db.txt"
expect_text esperar-claro "controle positivo: o mesmo ct está na captura (as mensagens desta execução foram capturadas)" "$CT_A" "$TMP/capture.txt"
psql_dev -c "SELECT DISTINCT key_version FROM messages WHERE room = ${ROOM_ID:-0}" >"$TMP/kv.txt"
check "o banco tem as 2 mensagens da sala" test "$(grep -c . "$TMP/bodies.txt")" = "2"
envelopes_ok() {
  node -e '
    const { parseEnvelope } = require("./shared/e2ee");
    const lines = require("fs").readFileSync(process.argv[1], "utf8").split("\n").filter(Boolean);
    for (const body of lines) parseEnvelope(body);
    process.exit(lines.length > 0 ? 0 : 1);
  ' "$TMP/bodies.txt" 2>"$TMP/envelopes.err" || { sed 's/^/         | /' "$TMP/envelopes.err"; return 1; }
}
check "cada mensagem no banco é só o envelope E2EE v1 {v,kv,iv,ct,sig}" envelopes_ok
check "versão da chave gravada = 1" test "$(cat "$TMP/kv.txt")" = "1"
echo "         exemplo do que o banco guarda: $(head -c 120 "$TMP/bodies.txt")…"

echo
if [ "$FAILS" -eq 0 ]; then echo "RESULTADO: todas as provas passaram"; else echo "RESULTADO: $FAILS prova(s) falharam"; fi
[ "$FAILS" -eq 0 ]
