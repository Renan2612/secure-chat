#!/usr/bin/env bash
# Provas das Etapas 4b-1 (E2EE), 4b-2 (remoção e troca da chave) e 5
# (privacidade: efêmeras, nome da sala cifrado, logs) contra a stack NO AR
# (docker compose --env-file backend/.env up --build). Termina com código
# != 0 se qualquer prova falhar.
#
# Uso: scripts/verify-e2ee.sh
#      MUTATION=plain-envelope scripts/verify-e2ee.sh      (deve FALHAR)
#      MUTATION=no-encrypt scripts/verify-e2ee.sh          (deve FALHAR)
#      MUTATION=reuse-old-key scripts/verify-e2ee.sh       (deve FALHAR: cliente reaproveita a chave na rotação)
#      MUTATION=server-no-rotation scripts/verify-e2ee.sh  (deve FALHAR: servidor não exige a rotação)
#      MUTATION=server-no-purge scripts/verify-e2ee.sh     (deve FALHAR: servidor não apaga as expiradas)
#      KEEP_CAPTURE=capturas scripts/verify-e2ee.sh        (guarda a captura)
#
# O backend é RECRIADO no início com o relógio de teste (E2EE_TEST_CLOCK,
# scripts/lib/test-clock.compose.yml; as mutações de servidor somam a flag
# delas) e devolvido ao normal na saída, conferindo que nenhuma flag ficou.
# Recriar também zera o limite de tentativas de /register e /login.
# Sem sudo: a captura usa o dumpcap como usuário do grupo wireshark.
# Cria três usuários (@example.invalid, senhas aleatórias só em variáveis) e
# uma sala temporários; Alice, Bob e Carol (três ws-client) trocam mensagens
# com marcadores únicos enquanto o tráfego proxy → backend (rede interna do
# Docker, porta 8000, em HTTP puro de propósito) é capturado. Depois a Alice
# (dona) remove o Bob pela API; o servidor exige a troca da chave e os
# clientes que ficaram rotacionam sozinhos (v2); a Alice manda um marcador
# novo, já na v2. Prova:
#   (a) os marcadores NÃO aparecem em nenhuma coluna do banco nem na captura
#       da rede interna — nem em claro, nem dentro de base64 decodificado —
#       com controles positivos (a captura tem tráfego, o upgrade e o JSON do
#       protocolo aparecem em claro; o detector acha o marcador codificado);
#   (b) cada cliente decifrou a mensagem do outro;
#   (c) o banco só tem o envelope (estrutura E2EE v1, key_version 1 e 2);
#   (4b-2) o servidor exigiu a rotação; a v2 não tem wrap para o Bob; o
#       marcador da v2 não aparece no banco nem na captura; o Bob, com o
#       keystore inteiro (todas as chaves antigas) e todos os pacotes da v2,
#       não decifra nada novo (controle positivo: ele ainda lê a v1, que já
#       tinha); a Carol, que ficou, ainda lê o texto antigo (v1) e o novo.
#   (5) a Alice manda uma mensagem com /ttl 1min; a Carol a vê com a
#       expiração; o relógio de teste do backend avança (SIGUSR2) e ela some
#       do histórico E do banco (expurgo); o nome da sala NÃO aparece em
#       claro no banco nem na captura (só cifrado; a Carol o lê); os logs
#       de todos os contêineres não têm e-mails, nome da sala, marcadores,
#       cookie nem o IP do cliente.
# Tudo o que foi criado é APAGADO na saída (trap), inclusive em falha.
# Gasta 7 tentativas do limite de /register e /login por IP (20 / 15 min);
# como o backend é recriado no início, o limite começa zerado.
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
CLIENT_MUTATION=""
SERVER_OVERRIDES=(-f docker-compose.yml -f scripts/lib/test-clock.compose.yml)
case "$MUTATION" in
  "") ;;
  server-no-rotation | server-no-purge) SERVER_OVERRIDES+=(-f "scripts/mutations/$MUTATION.compose.yml") ;;
  plain-envelope | no-encrypt | reuse-old-key) CLIENT_MUTATION="scripts/mutations/$MUTATION.js" ;;
  *) echo "erro: MUTATION inválida: $MUTATION" >&2; exit 2 ;;
esac
# Uma mutação que não carrega rodaria o script SEM mutação (e "passaria").
[ -z "$CLIENT_MUTATION" ] || [ -f "$CLIENT_MUTATION" ] || { echo "erro: $CLIENT_MUTATION não existe" >&2; exit 2; }
for file in "${SERVER_OVERRIDES[@]}"; do
  [ "$file" = -f ] || [ -f "$file" ] || { echo "erro: $file não existe" >&2; exit 2; }
done
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
# Nome da sala que NÃO é prefixo de nenhum e-mail temporário (os e-mails
# aparecem no banco e na captura; senão a prova do nome cifrado acusaria um
# falso positivo).
ROOM_NAME="SALA-VERIFY-$(openssl rand -hex 8)"
A_EMAIL="verify-e2ee-$STAMP-a@example.invalid"
B_EMAIL="verify-e2ee-$STAMP-b@example.invalid"
C_EMAIL="verify-e2ee-$STAMP-c@example.invalid"
A_PASSWORD="$(openssl rand -hex 16)"; B_PASSWORD="$(openssl rand -hex 16)"; C_PASSWORD="$(openssl rand -hex 16)"
A_KEYPASS="$(openssl rand -hex 16)"; B_KEYPASS="$(openssl rand -hex 16)"; C_KEYPASS="$(openssl rand -hex 16)"
MARK_A="MARCADOR-ALICE-$(openssl rand -hex 8)"
MARK_B="MARCADOR-BOB-$(openssl rand -hex 8)"
MARK_C="MARCADOR-V2-$(openssl rand -hex 8)"
MARK_E="MARCADOR-EFEMERA-$(openssl rand -hex 8)"
CAPTURE="$TMP/interna.pcapng"
PIDS=()

psql_dev() { "${COMPOSE[@]}" exec -T db psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -qAt "$@"; }

cleanup() {
  local rc=$?
  trap - EXIT INT TERM HUP PIPE
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
  if ! psql_dev -v a="$A_EMAIL" -v b="$B_EMAIL" -v c="$C_EMAIL" >/dev/null 2>"$TMP/cleanup.err" <<'SQL'
WITH u AS (SELECT id FROM users WHERE email IN (:'a', :'b', :'c')),
     r AS (SELECT id AS room FROM rooms WHERE created_by IN (SELECT id FROM u)
           UNION SELECT room FROM rooms_users WHERE user_id IN (SELECT id FROM u)),
     w AS (DELETE FROM room_key_wraps WHERE room IN (SELECT room FROM r)
           OR recipient_id IN (SELECT id FROM u) OR sender_id IN (SELECT id FROM u)),
     m AS (DELETE FROM messages WHERE user_id IN (SELECT id FROM u) OR room IN (SELECT room FROM r)),
     ru AS (DELETE FROM rooms_users WHERE room IN (SELECT room FROM r) OR user_id IN (SELECT id FROM u)),
     s AS (DELETE FROM user_sessions WHERE (sess->>'userId')::int IN (SELECT id FROM u)),
     k AS (DELETE FROM user_keys WHERE user_id IN (SELECT id FROM u)),
     bn AS (DELETE FROM room_bans WHERE user_id IN (SELECT id FROM u))
SELECT 1;
DELETE FROM room_key_versions WHERE room IN (SELECT id FROM rooms WHERE created_by IN (SELECT id FROM users WHERE email IN (:'a', :'b', :'c')));
DELETE FROM room_key_versions WHERE created_by IN (SELECT id FROM users WHERE email IN (:'a', :'b', :'c'));
DELETE FROM rooms WHERE created_by IN (SELECT id FROM users WHERE email IN (:'a', :'b', :'c'))
   OR owner_id IN (SELECT id FROM users WHERE email IN (:'a', :'b', :'c'));
DELETE FROM users WHERE email IN (:'a', :'b', :'c');
SQL
  then
    echo "ERRO: a limpeza do banco falhou:" >&2
    sed 's/^/  | /' "$TMP/cleanup.err" >&2
    rc=3
  fi
  local left
  left="$(psql_dev -v a="$A_EMAIL" -v b="$B_EMAIL" -v c="$C_EMAIL" 2>/dev/null <<<"SELECT COUNT(*) FROM users WHERE email IN (:'a', :'b', :'c');" || echo "?")"
  if [ "$left" = "0" ]; then
    echo "(usuários, sala e mensagens temporários removidos do banco)"
  else
    echo "ERRO: usuários temporários ainda no banco ($A_EMAIL, $B_EMAIL, $C_EMAIL)" >&2
    rc=3
  fi
  if [ -n "${KEEP_CAPTURE:-}" ] && [ -s "$CAPTURE" ]; then
    local kept="$KEEP_CAPTURE/verify-e2ee-$STAMP${MUTATION:+-$MUTATION}.pcapng"
    if mkdir -p "$KEEP_CAPTURE" && cp "$CAPTURE" "$kept"; then echo "(captura guardada em $kept)"; else echo "aviso: não foi possível guardar a captura em $KEEP_CAPTURE" >&2; fi
  fi
  if [ -n "${BACKEND_MUTATED:-}" ]; then
    # Devolve o backend ao normal (sem nenhuma flag de teste) e confere.
    if "${COMPOSE[@]}" up -d --no-deps --wait backend >/dev/null 2>"$TMP/restore.err" &&
      ! "${COMPOSE[@]}" exec -T backend sh -c 'env | grep -q "^E2EE_TEST_"' 2>/dev/null; then
      echo "(backend recriado sem as flags de teste)"
    else
      echo "ERRO: não foi possível devolver o backend ao normal; rode: docker compose --env-file backend/.env up -d --no-deps backend" >&2
      rc=3
    fi
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
BACKEND_MUTATED=1 # a limpeza recria o backend sem as flags, mesmo se o passo abaixo falhar no meio
# A varredura dos logs começa ANTES da recriação: o aviso de início do
# backend é o controle positivo (num fluxo sem erro ninguém registra nada).
LOG_SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if "${COMPOSE[@]}" "${SERVER_OVERRIDES[@]}" up -d --no-deps --wait backend >/dev/null 2>"$TMP/mutate.err"; then
  ok "backend recriado com o relógio de teste${MUTATION:+ e a flag da mutação $MUTATION}"
  check "o relógio de teste está mesmo ativo no contêiner" test "$("${COMPOSE[@]}" exec -T backend printenv E2EE_TEST_CLOCK 2>/dev/null)" = "inseguro-so-para-teste"
  case "$MUTATION" in
    server-no-rotation) check "a flag E2EE_TEST_SKIP_ROTATION está ativa" test "$("${COMPOSE[@]}" exec -T backend printenv E2EE_TEST_SKIP_ROTATION 2>/dev/null)" = "inseguro-so-para-teste" ;;
    server-no-purge) check "a flag E2EE_TEST_SKIP_PURGE está ativa" test "$("${COMPOSE[@]}" exec -T backend printenv E2EE_TEST_SKIP_PURGE 2>/dev/null)" = "inseguro-so-para-teste" ;;
  esac
else
  ko "recriar o backend com o relógio de teste"; sed 's/^/         | /' "$TMP/mutate.err"; exit 1
fi
CA="$TMP/ca.crt"
if scripts/export-ca.sh "$CA" >/dev/null; then ok "CA raiz exportada"; else ko "exportar a CA"; exit 1; fi
register() { # register EMAIL SENHA NOME → HTTP status
  printf '{"email":"%s","password":"%s","name":"%s"}' "$1" "$2" "$3" >"$TMP/register.json"
  curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" -H 'Content-Type: application/json' -H "Origin: $BASE" \
    --data-binary "@$TMP/register.json" "$BASE/api/register"
}
check "usuária temporária Alice cadastrada" test "$(register "$A_EMAIL" "$A_PASSWORD" "Alice e2ee")" = "201"
check "usuário temporário Bob cadastrado" test "$(register "$B_EMAIL" "$B_PASSWORD" "Bob e2ee")" = "201"
check "usuária temporária Carol cadastrada" test "$(register "$C_EMAIL" "$C_PASSWORD" "Carol e2ee")" = "201"
rm -f "$TMP/register.json"

section "Captura da rede interna proxy → backend ($BRIDGE, tcp port 8000)"
dumpcap -q -i "$BRIDGE" -f "tcp port 8000" -a duration:240 -w "$CAPTURE" 2>"$TMP/dumpcap.err" &
DUMPCAP=$!
PIDS+=("$DUMPCAP")
wait_for "$TMP/dumpcap.err" "Capturing on" 10 || sleep 1

# Um ws-client com stdin num FIFO (as linhas são escritas pelo script).
start_client() { # start_client NOME EMAIL SENHA SENHA-CIFRAGEM ARGS...
  local name="$1" email="$2" password="$3" keypass="$4"
  shift 4
  mkfifo "$TMP/$name.in"
  local preload=()
  [ -n "$CLIENT_MUTATION" ] && preload=(--require "./$CLIENT_MUTATION")
  CHAT_PASSWORD="$password" CHAT_KEY_PASSPHRASE="$keypass" HOME="$TMP/home-$name" timeout 200 node "${preload[@]}" \
    backend/tools/ws-client.js --server "$BASE/api" --ca "$CA" --origin "$BASE" --email "$email" \
    --keystore "$TMP/home-$name/keystore.json" "$@" <"$TMP/$name.in" >"$TMP/$name.out" 2>&1 &
  PIDS+=($!)
  eval "${name}_PID=$!"
}

mkdir -p "$TMP/home-alice" "$TMP/home-bob" "$TMP/home-carol"
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

# Carol entra; a Alice a aprova. Alice e Carol conferem e confirmam a chave
# uma da outra (/safety + /trust): a partir da v2 só se aceita a chave
# trocada por alguém VERIFICADO, e qualquer uma das duas pode rotacionar.
start_client carol "$C_EMAIL" "$C_PASSWORD" "$C_KEYPASS" --room "${ROOM_ID:-0}" --join "${INVITE:-x}"
exec {CAROL_IN}>"$TMP/carol.in"
wait_for "$TMP/carol.out" "logado como" 30
C_ID="$(sed -nE 's/.*logado como .* \(usuário ([0-9]+)\).*/\1/p' "$TMP/carol.out")"
wait_for "$TMP/alice.out" "/approve ${C_ID:-x}" 30
echo "/approve ${C_ID:-x}" >&"$ALICE_IN"
wait_for "$TMP/carol.out" "chave da sala [0-9]+ disponível" 30
check "Carol (usuária ${C_ID:-?}) recebeu a chave v1 após o /approve" grep -q "chave da sala ${ROOM_ID:-x} disponível (v1" "$TMP/carol.out"
printf '/safety %s\n/trust %s\n' "${C_ID:-x}" "${C_ID:-x}" >&"$ALICE_IN"
printf '/safety %s\n/trust %s\n' "${A_ID:-x}" "${A_ID:-x}" >&"$CAROL_IN"
wait_for "$TMP/alice.out" "usuário ${C_ID:-x} marcado como verificado" 15
wait_for "$TMP/carol.out" "usuário ${A_ID:-x} marcado como verificado" 15
check "Alice e Carol conferiram e confirmaram a chave uma da outra" grep -q "usuário ${A_ID:-x} marcado como verificado" "$TMP/carol.out"

echo "$MARK_A" >&"$ALICE_IN"
wait_for "$TMP/bob.out" "$MARK_A" 15
wait_for "$TMP/carol.out" "$MARK_A" 15
echo "$MARK_B" >&"$BOB_IN"
wait_for "$TMP/alice.out" "$MARK_B" 15
wait_for "$TMP/carol.out" "$MARK_B" 15

# A Alice (dona) remove o Bob pela API, com uma sessão própria: o servidor
# exige a troca da chave (ROTATION_PENDING) e quem ficou rotaciona sozinho.
api_alice() { # api_alice MÉTODO CAMINHO [CORPO] → HTTP status
  curl -s -o "$TMP/api.out" -w '%{http_code}' --cacert "$CA" -b "$TMP/alice.cookies" -c "$TMP/alice.cookies" \
    -H 'Content-Type: application/json' -H "Origin: $BASE" -X "$1" ${3:+--data-binary "$3"} "$BASE/api$2"
}
printf '{"email":"%s","password":"%s"}' "$A_EMAIL" "$A_PASSWORD" >"$TMP/login.json"
check "a Alice abriu uma sessão para a remoção" test "$(api_alice POST /login "@$TMP/login.json")" = "200"
rm -f "$TMP/login.json"
check "a Alice removeu o Bob (DELETE /rooms/${ROOM_ID:-?}/members/${B_ID:-?})" test "$(api_alice DELETE "/rooms/${ROOM_ID:-0}/members/${B_ID:-0}")" = "200"
# Sem logout aqui: o logout encerra TODAS as conexões do usuário (inclusive
# o ws-client da Alice). A sessão auxiliar é apagada na limpeza (trap).
wait_for "$TMP/bob.out" "não é mais membro" 15
wait_for "$TMP/alice.out" "chave da sala ${ROOM_ID:-x} disponível \(v2" 20
wait_for "$TMP/carol.out" "chave da sala ${ROOM_ID:-x} disponível \(v2" 20
echo "$MARK_C" >&"$ALICE_IN"
wait_for "$TMP/carol.out" "$MARK_C" 15

# (5) Efêmera: /ttl 1min na Alice; a Carol a vê com a expiração. Depois o
# relógio de teste do backend avança 1 h (SIGUSR2), o que vence a mensagem
# e roda o expurgo.
printf '/ttl 1min\n%s\n' "$MARK_E" >&"$ALICE_IN"
wait_for "$TMP/carol.out" "\[expira [^]]*\]: $MARK_E" 15
EPH_ID="$(psql_dev -c "SELECT id FROM messages WHERE room = ${ROOM_ID:-0} AND expires_at IS NOT NULL ORDER BY id DESC LIMIT 1")"
EPH_ROWS_BEFORE="$(psql_dev -c "SELECT COUNT(*) FROM messages WHERE id = ${EPH_ID:-0}")"
api_alice GET "/messages/${ROOM_ID:-0}?limit=100" >/dev/null
HISTORY_BEFORE="$(node -e 'try{process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).map(m=>m.idmessage).join(","))}catch{}' "$TMP/api.out")"
"${COMPOSE[@]}" exec -T backend kill -USR2 1 2>"$TMP/kill.err"; KILL_RC=$?
sleep 2
EPH_ROWS_AFTER="$(psql_dev -c "SELECT COUNT(*) FROM messages WHERE id = ${EPH_ID:-0}")"
HISTORY_STATUS="$(api_alice GET "/messages/${ROOM_ID:-0}?limit=100")"
HISTORY_AFTER="$(node -e 'try{process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).map(m=>m.idmessage).join(","))}catch{}' "$TMP/api.out")"
sleep 1
exec {ALICE_IN}>&- {BOB_IN}>&- {CAROL_IN}>&-   # fim da entrada: os clientes saem e fazem logout
wait "$alice_PID"; A_STATUS=$?
wait "$bob_PID"; B_STATUS=$?
wait "$carol_PID"; C_STATUS=$?
kill -INT "$DUMPCAP" 2>/dev/null; wait "$DUMPCAP" 2>/dev/null
PACKETS="$(tshark -r "$CAPTURE" 2>/dev/null | wc -l)"
DROPPED="$(sed -nE 's#.*received/dropped on interface.*: [0-9]+/([0-9]+).*#\1#p' "$TMP/dumpcap.err" | head -n 1)"
# Texto da captura: "text" (HTTP: upgrade e corpos da API) e
# websocket.payload.text (os quadros WebSocket INTEIROS). Só o "text" não
# basta: é o rótulo de exibição, cortado em 240 caracteres, e o ct de um
# MSG_SEND começa perto disso (com ids maiores, ficava de fora da varredura).
tshark -r "$CAPTURE" -d tcp.port==8000,http -T fields -e text -e websocket.payload.text 2>/dev/null >"$TMP/capture.txt"

section "(b) cada cliente decifrou a mensagem do outro"
check "Bob mostra a mensagem da Alice decifrada e assinada por ela" grep -qF "usuário ${A_ID:-?} [não verificado]: $MARK_A" "$TMP/bob.out"
check "Alice mostra a mensagem do Bob decifrada e assinada por ele" grep -qF "usuário ${B_ID:-?} [não verificado]: $MARK_B" "$TMP/alice.out"
check "Carol mostra as mensagens da Alice e do Bob (v1)" grep -qF "usuário ${B_ID:-?} [não verificado]: $MARK_B" "$TMP/carol.out"
check "os três clientes terminaram sem erro (saídas $A_STATUS, $B_STATUS e $C_STATUS)" test "$A_STATUS:$B_STATUS:$C_STATUS" = "0:0:0"

section "(a) captura da rede interna (onde o TLS já terminou)"
check "controle positivo: a captura tem tráfego ($PACKETS pacotes)" test "$PACKETS" -gt 0
check "a captura não perdeu pacotes (descartados: ${DROPPED:-?})" test "${DROPPED:-x}" = "0"
expect_text esperar-claro "controle positivo: o upgrade do /ws aparece em claro" "Upgrade: websocket" "$CAPTURE" "$TMP/capture.txt"
expect_text esperar-claro "controle positivo: o JSON do protocolo aparece em claro (MSG_SEND)" '"type":"MSG_SEND"' "$TMP/capture.txt"
printf '%s' "$MARK_A" | node -e 'process.stdout.write(Buffer.from(require("fs").readFileSync(0)).toString("base64url"))' >"$TMP/selftest.txt"
expect_text esperar-claro "controle positivo do detector: acha o marcador codificado em base64url" "$MARK_A" "$TMP/selftest.txt"
expect_text esperar-cifrado "marcador da Alice não aparece na captura" "$MARK_A" "$CAPTURE" "$TMP/capture.txt"
expect_text esperar-cifrado "marcador do Bob não aparece na captura" "$MARK_B" "$CAPTURE" "$TMP/capture.txt"
expect_text esperar-cifrado "marcador da v2 (depois da remoção) não aparece na captura" "$MARK_C" "$CAPTURE" "$TMP/capture.txt"
expect_text esperar-cifrado "marcador da efêmera não aparece na captura" "$MARK_E" "$CAPTURE" "$TMP/capture.txt"
expect_text esperar-cifrado "o nome da sala não aparece em claro na captura" "$ROOM_NAME" "$CAPTURE" "$TMP/capture.txt"

section "(a) e (c) banco de dados"
: >"$TMP/db.txt"
TABLES="$(psql_dev -c "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1")"
check "lista de tabelas do banco obtida ($(wc -w <<<"$TABLES") tabelas)" test "$(wc -w <<<"$TABLES")" -ge 8
DUMP_FAILS=0
for table in $TABLES; do
  psql_dev -c "SELECT row_to_json(t)::text FROM \"$table\" t" >>"$TMP/db.txt" || { ko "despejo da tabela $table falhou"; DUMP_FAILS=1; }
done
check "todas as tabelas foram despejadas para a varredura" test "$DUMP_FAILS" = 0
# Etapa 5 (A3): o nome da sala deixou de ser metadado em claro (era o
# controle positivo até a 4b-2). Controle positivo novo: o name_env (cifrado)
# desta sala está no despejo, e a Carol leu o nome decifrado.
expect_text esperar-cifrado "o nome da sala NÃO aparece em claro em nenhuma coluna (só cifrado)" "$ROOM_NAME" "$TMP/db.txt"
NAME_CT="$(psql_dev -c "SELECT name_env FROM rooms WHERE id = ${ROOM_ID:-0}" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{try{process.stdout.write(JSON.parse(d).ct.slice(0,40))}catch{}})')"
expect_text esperar-claro "controle positivo: o name_env cifrado desta sala está no despejo do banco" "$NAME_CT" "$TMP/db.txt"
check "controle positivo: a Carol leu o nome da sala decifrado" grep -qF "«$ROOM_NAME»" "$TMP/carol.out"
expect_text esperar-cifrado "marcador da efêmera não aparece em nenhuma coluna" "$MARK_E" "$TMP/db.txt"
expect_text esperar-cifrado "marcador da Alice não aparece em nenhuma coluna" "$MARK_A" "$TMP/db.txt"
expect_text esperar-cifrado "marcador do Bob não aparece em nenhuma coluna" "$MARK_B" "$TMP/db.txt"
expect_text esperar-cifrado "marcador da v2 não aparece em nenhuma coluna" "$MARK_C" "$TMP/db.txt"
psql_dev -c "SELECT message FROM messages WHERE room = ${ROOM_ID:-0} ORDER BY id" >"$TMP/bodies.txt"
# Controle positivo amarrado a ESTA execução: o texto cifrado exato que o
# banco guardou precisa aparecer no despejo e na captura (prova que as
# mensagens com os marcadores foram mesmo varridas).
CT_A="$(head -n 1 "$TMP/bodies.txt" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{try{process.stdout.write(JSON.parse(d).ct.slice(0,40))}catch{}})')"
expect_text esperar-claro "controle positivo: o ct da 1ª mensagem desta execução está no despejo do banco" "$CT_A" "$TMP/db.txt"
expect_text esperar-claro "controle positivo: o mesmo ct está na captura (as mensagens desta execução foram capturadas)" "$CT_A" "$TMP/capture.txt"
psql_dev -c "SELECT DISTINCT key_version FROM messages WHERE room = ${ROOM_ID:-0} ORDER BY 1" | paste -sd, >"$TMP/kv.txt"
check "o banco tem as 3 mensagens da sala (2 na v1, 1 na v2)" test "$(grep -c . "$TMP/bodies.txt")" = "3"
envelopes_ok() {
  node -e '
    const { parseEnvelope } = require("./shared/e2ee");
    const lines = require("fs").readFileSync(process.argv[1], "utf8").split("\n").filter(Boolean);
    for (const body of lines) parseEnvelope(body);
    process.exit(lines.length > 0 ? 0 : 1);
  ' "$TMP/bodies.txt" 2>"$TMP/envelopes.err" || { sed 's/^/         | /' "$TMP/envelopes.err"; return 1; }
}
check "cada mensagem no banco é só o envelope E2EE v2 {v,kv,iv,ct,sig,exp}" envelopes_ok
check "versões da chave gravadas = 1 e 2 (a v2 nasceu da rotação)" test "$(cat "$TMP/kv.txt")" = "1,2"
echo "         exemplo do que o banco guarda: $(head -c 120 "$TMP/bodies.txt")…"

section "(4b-2) remoção do Bob e troca da chave"
check "o servidor exigiu a troca da chave: a Carol recebeu o aviso (ROTATION_PENDING)" grep -q "evento: alguém saiu da sala ${ROOM_ID:-x}" "$TMP/carol.out"
check "o Bob foi avisado da remoção e desinscrito" grep -q "não é mais membro da sala ${ROOM_ID:-x}" "$TMP/bob.out"
both_v2() { grep -q "disponível (v2" "$TMP/alice.out" && grep -q "disponível (v2" "$TMP/carol.out"; }
check "Alice e Carol passaram à chave v2 (rotação automática)" both_v2
V2_TO_BOB="$(psql_dev -c "SELECT COUNT(*) FROM room_key_wraps WHERE room = ${ROOM_ID:-0} AND version = 2 AND recipient_id = ${B_ID:-0}")"
V2_WRAPS="$(psql_dev -c "SELECT COUNT(*) FROM room_key_wraps WHERE room = ${ROOM_ID:-0} AND version = 2")"
check "a v2 tem wraps só para quem ficou (${V2_WRAPS:-?} wraps, ${V2_TO_BOB:-?} para o Bob)" test "${V2_WRAPS:-0}:${V2_TO_BOB:-x}" = "2:0"
check "Carol mostra o marcador da v2, decifrado e verificado" grep -qF "usuário ${A_ID:-?} [verificado]: $MARK_C" "$TMP/carol.out"
# Tudo o que veio DEPOIS da remoção e que um removido com acesso ao banco ou
# à rede teria: a mensagem nova (qualquer que seja o kv dela: numa mutação
# sem rotação, ela sai na v1) e TODOS os wraps da v2 (de qualquer
# destinatário), com as chaves públicas dos remetentes. "Antes" = as duas
# primeiras mensagens (v1).
V2_RC=0; V1_RC=0
psql_dev >"$TMP/v2.jsonl" <<SQL || V2_RC=$?
SELECT json_build_object('kind','message','room',m.room,'from',m.user_id,'cid',m.cid,'body',m.message,'senderEcdsaPub',k.ecdsa_pub)::text
  FROM messages m JOIN user_keys k ON k.user_id = m.user_id WHERE m.room = ${ROOM_ID:-0} ORDER BY m.id OFFSET 2;
SELECT json_build_object('kind','wrap','room',w.room,'version',w.version,'recipientId',w.recipient_id,'senderId',w.sender_id,
       'ephPub',w.eph_pub,'iv',w.iv,'wrapped',w.wrapped,'sig',w.sig,'senderEcdsaPub',k.ecdsa_pub)::text
  FROM room_key_wraps w JOIN user_keys k ON k.user_id = w.sender_id WHERE w.room = ${ROOM_ID:-0} AND w.version = 2;
SQL
psql_dev >"$TMP/v1.jsonl" <<SQL || V1_RC=$?
SELECT json_build_object('kind','message','room',m.room,'from',m.user_id,'cid',m.cid,'body',m.message,'senderEcdsaPub',k.ecdsa_pub)::text
  FROM messages m JOIN user_keys k ON k.user_id = m.user_id WHERE m.room = ${ROOM_ID:-0} ORDER BY m.id LIMIT 2;
SQL
count_kind() { grep -c "\"kind\" *: *\"$1\"" "$2"; }
packets_ok() {
  [ "$V2_RC:$V1_RC" = "0:0" ] && [ "$(count_kind message "$TMP/v2.jsonl")" = 1 ] &&
    [ "$(count_kind wrap "$TMP/v2.jsonl")" = "${V2_WRAPS:-x}" ] && [ "$(count_kind message "$TMP/v1.jsonl")" = 2 ]
}
check "pacotes capturados do banco: 1 mensagem de depois da remoção + os ${V2_WRAPS:-?} wraps da v2; 2 mensagens de antes" packets_ok
try_decrypt() { # try_decrypt KEYSTORE SENHA < candidatos → linhas ok/fail
  TRY_KEYPASS="$2" node scripts/lib/try-decrypt.js "$1"
}
BOB_V2="$(try_decrypt "$TMP/home-bob/keystore.json" "$B_KEYPASS" <"$TMP/v2.jsonl")"; BOB_V2_RC=$?
BOB_V1="$(try_decrypt "$TMP/home-bob/keystore.json" "$B_KEYPASS" <"$TMP/v1.jsonl")"; BOB_V1_RC=$?
CAROL_V1="$(try_decrypt "$TMP/home-carol/keystore.json" "$C_KEYPASS" <"$TMP/v1.jsonl")"; CAROL_V1_RC=$?
CAROL_V2="$(try_decrypt "$TMP/home-carol/keystore.json" "$C_KEYPASS" <"$TMP/v2.jsonl")"; CAROL_V2_RC=$?
check "o detector de decifragem rodou sem erro nas quatro tentativas" test "$BOB_V2_RC:$BOB_V1_RC:$CAROL_V1_RC:$CAROL_V2_RC" = "0:0:0:0"
removed_blind() { [ "$BOB_V2_RC" = 0 ] && [ -n "$BOB_V2" ] && ! grep -q '^ok' <<<"$BOB_V2"; }
check "(b) o removido, com o keystore inteiro e todos os pacotes de depois da remoção, não decifra nada novo" removed_blind
check "controle positivo: com o mesmo keystore o Bob ainda lê a v1 (o removido retém o que já recebeu)" grep -qxF "ok $MARK_A" <<<"$BOB_V1"
check "(c) quem ficou (Carol) ainda lê o texto antigo da v1 depois da rotação" grep -qxF "ok $MARK_B" <<<"$CAROL_V1"
check "Carol lê o marcador novo com o próprio keystore" grep -qxF "ok $MARK_C" <<<"$CAROL_V2"
check "controle positivo dos wraps: a Carol abre exatamente um wrap da v2 (o dela)" test "$(grep -cx 'ok wrap' <<<"$CAROL_V2")" = 1

section "(5) mensagem efêmera e expurgo"
check "Carol mostrou a efêmera da Alice com a expiração" grep -qE "\[expira [^]]*\]: $MARK_E" "$TMP/carol.out"
check "a efêmera foi gravada com expires_at (id ${EPH_ID:-?})" test -n "${EPH_ID:-}" -a "${EPH_ROWS_BEFORE:-0}" = 1
in_list() { [[ ",$2," == *",$1,"* ]]; }
check "controle positivo: antes do expurgo o histórico tinha a efêmera" in_list "${EPH_ID:-x}" "$HISTORY_BEFORE"
check "o relógio de teste do backend avançou (SIGUSR2 entregue)" test "$KILL_RC" = 0
not_in_history() { [ "$HISTORY_STATUS" = 200 ] && [ -n "$HISTORY_AFTER" ] && ! in_list "${EPH_ID:-x}" "$HISTORY_AFTER"; }
check "depois de vencer, a efêmera some do histórico (as outras continuam: ${HISTORY_AFTER:-vazio})" not_in_history
check "depois do expurgo, a efêmera some do BANCO (linhas com o id ${EPH_ID:-?}: ${EPH_ROWS_AFTER:-?})" test "${EPH_ROWS_AFTER:-x}" = 0

section "(5) logs de todos os contêineres (desde a recriação do backend)"
"${COMPOSE[@]}" logs --no-color --since "$LOG_SINCE" >"$TMP/logs.txt" 2>&1; LOGS_RC=$?
check "logs obtidos ($(wc -l <"$TMP/logs.txt") linhas)" test "$LOGS_RC" = 0 -a -s "$TMP/logs.txt"
check "controle positivo: o log tem o aviso do relógio de teste do backend" grep -q "E2EE_TEST_CLOCK definido" "$TMP/logs.txt"
CLIENT_IP="$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' "$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT" --filter label=com.docker.compose.network=borda | head -n 1)" 2>/dev/null)"
check "IP com que os clientes chegam ao proxy obtido (${CLIENT_IP:-?})" test -n "$CLIENT_IP"
for needle in "$A_EMAIL" "$B_EMAIL" "$C_EMAIL" "$ROOM_NAME" "$MARK_A" "$MARK_B" "$MARK_C" "$MARK_E"; do
  expect_text esperar-cifrado "log sem: $needle" "$needle" "$TMP/logs.txt"
done
if [ -n "$CLIENT_IP" ]; then
  if grep -qF "$CLIENT_IP" "$TMP/logs.txt"; then ko "o IP do cliente ($CLIENT_IP) aparece no log"; else ok "o IP do cliente ($CLIENT_IP) não aparece no log"; fi
fi
if grep -qE 'sid=s%3A|sid=s:' "$TMP/logs.txt"; then ko "um cookie de sessão aparece no log"; else ok "nenhum cookie de sessão no log"; fi

echo
if [ "$FAILS" -eq 0 ]; then echo "RESULTADO: todas as provas passaram"; else echo "RESULTADO: $FAILS prova(s) falharam"; fi
[ "$FAILS" -eq 0 ]
