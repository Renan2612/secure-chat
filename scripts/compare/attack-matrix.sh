#!/usr/bin/env bash
# Matriz de ataques "antes e depois" (Etapa 6, A3). Roda o MESMO conjunto de
# ataques contra o projeto ORIGINAL (esperado: vulnerável) e contra a stack
# FINAL (esperado: bloqueado), e grava evidencias/etapa6/matriz.{md,json}.
#
# Código de saída: 0 se TODA asserção da versão FINAL bate (e os controles
# positivos valem); 1 se alguma falha. Se o ORIGINAL não for vulnerável em
# algum item, isso é reportado com honestidade, mas NÃO derruba a matriz
# (o original é um alvo externo, fora do nosso controle).
#
# Regra de segurança: só mira 127.0.0.1/localhost (trava em lib-local-guard).
#
# Mutações (devem sair com != 0; o plano pede mostrar as duas):
#   MUTATION=skip-defense    sobe a FINAL com a autorização por sala
#                            desligada → a asserção "ler sala alheia" falha.
#   MUTATION=nonlocal-target aponta o alvo para um host não-local → a trava
#                            aborta antes de qualquer ataque (saída 3).
set -uo pipefail
umask 077
cd "$(dirname "$0")/../.."
source scripts/compare/lib-local-guard.sh

MUTATION="${MUTATION:-}"
ORIG_API="http://127.0.0.1:18000"
FINAL_ORIGIN="https://localhost"
[ "$MUTATION" = nonlocal-target ] && FINAL_ORIGIN="https://attacker.example"   # mutação (ii)
FINAL_API="$FINAL_ORIGIN/api"
FINAL_HOST="$(host_of "$FINAL_ORIGIN")"
FINAL_WS="wss://$FINAL_HOST/ws"

# Na mutação (ii), exercita ANTES a trava do cliente Node (defesa em
# profundidade): com um alvo não-local, matrix.js tem de sair com 3 por
# conta própria. Sem isto, só a trava bash abaixo seria testada.
if [ "$MUTATION" = nonlocal-target ]; then
  printf '{"final":{"api":"%s","ws":"%s"}}' "$FINAL_API" "$FINAL_WS" | node attacks/matrix.js >/dev/null 2>&1
  if [ "$?" = 3 ]; then echo "trava do cliente Node (matrix.js) recusou o alvo não-local (saída 3)"; else echo "FALHA: matrix.js NÃO recusou o alvo não-local" >&2; exit 1; fi
fi

# TRAVA: alvo não-local aborta aqui, antes de subir nada ou atacar.
assert_local_targets "$ORIG_API" "$FINAL_ORIGIN" "$FINAL_WS"

for tool in docker node openssl curl dumpcap tshark; do
  command -v "$tool" >/dev/null || { echo "erro: '$tool' não encontrado" >&2; exit 2; }
done

OUT="evidencias/etapa6"; mkdir -p "$OUT"
TMP="$(mktemp -d)"
ROWS="$TMP/rows.jsonl"; : >"$ROWS"
COMPOSE_FINAL=(docker compose --env-file backend/.env)
[ "$MUTATION" = skip-defense ] && COMPOSE_FINAL=(docker compose --env-file backend/.env -f docker-compose.yml -f scripts/compare/skip-defense.compose.yml)
CA="$TMP/ca.crt"
DB_USER="$(sed -n 's/^DB_USER=//p' backend/.env | tail -n1)"; DB_USER="${DB_USER:-postgres}"
DB_NAME="$(sed -n 's/^DB_NAME=//p' backend/.env | tail -n1)"; DB_NAME="${DB_NAME:-secure_chat}"
psql_final() { "${COMPOSE_FINAL[@]}" exec -T db psql -U "$DB_USER" -d "$DB_NAME" -qAt -v ON_ERROR_STOP=1 "$@"; }
psql_orig() { docker compose -f scripts/compare/original.compose.yml exec -T db-orig psql -U postgres -d messagewebapp -qAt "$@"; }

cleanup() {
  local rc=$?
  trap - EXIT INT TERM HUP
  # Apaga do banco FINAL tudo o que a matriz criou (usuários atk-/snf-).
  # ON_ERROR_STOP=1 + aviso: uma limpeza que falha não pode passar calada
  # (deixaria usuários/salas de teste no banco).
  if ! psql_final >/dev/null 2>"$TMP/cleanup.err" <<'SQL'
WITH u AS (SELECT id FROM users WHERE email LIKE 'atk-%@example.invalid' OR email LIKE 'snf-%@example.invalid'),
     r AS (SELECT id AS room FROM rooms WHERE created_by IN (SELECT id FROM u) OR owner_id IN (SELECT id FROM u)
           UNION SELECT room FROM rooms_users WHERE user_id IN (SELECT id FROM u))
DELETE FROM rooms WHERE id IN (SELECT room FROM r);
DELETE FROM room_key_wraps WHERE recipient_id IN (SELECT id FROM users WHERE email LIKE 'atk-%@example.invalid' OR email LIKE 'snf-%@example.invalid') OR sender_id IN (SELECT id FROM users WHERE email LIKE 'atk-%@example.invalid' OR email LIKE 'snf-%@example.invalid');
DELETE FROM room_key_versions WHERE created_by IN (SELECT id FROM users WHERE email LIKE 'atk-%@example.invalid' OR email LIKE 'snf-%@example.invalid');
DELETE FROM messages WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'atk-%@example.invalid' OR email LIKE 'snf-%@example.invalid');
DELETE FROM rooms_users WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'atk-%@example.invalid' OR email LIKE 'snf-%@example.invalid');
DELETE FROM room_bans WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'atk-%@example.invalid' OR email LIKE 'snf-%@example.invalid');
DELETE FROM user_keys WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'atk-%@example.invalid' OR email LIKE 'snf-%@example.invalid');
DELETE FROM user_sessions WHERE (sess->>'userId')::int IN (SELECT id FROM users WHERE email LIKE 'atk-%@example.invalid' OR email LIKE 'snf-%@example.invalid');
DELETE FROM users WHERE email LIKE 'atk-%@example.invalid' OR email LIKE 'snf-%@example.invalid';
SQL
  then :; else
    echo "AVISO: a limpeza do banco final falhou; podem ter ficado usuários atk-/snf- (remova à mão):" >&2
    sed 's/^/  | /' "$TMP/cleanup.err" >&2
  fi
  if ! scripts/compare/stop-original.sh >/dev/null 2>"$TMP/stop.err"; then
    echo "AVISO: o teardown da stack do original falhou; ela pode ter ficado de pé em 127.0.0.1:18000" >&2
  fi
  rm -rf "$TMP"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

emit() { # emit ID TITULO ALVO ESPERA(vulneravel|bloqueado) OBS(vulneravel|bloqueado|inconclusivo) CONTROLE DETALHE
  ID="$1" TIT="$2" ALVO="$3" ESP="$4" OBS="$5" CTRL="$6" DET="$7" node -e '
    const o = (k) => process.env[k];
    process.stdout.write(JSON.stringify({ id:o("ID"), titulo:o("TIT"), alvo:o("ALVO"), esperado:o("ESP"),
      observado:o("OBS"), ok:o("OBS")===o("ESP"), controle:o("CTRL"), detalhe:o("DET") })+"\n");
  ' >>"$ROWS"
}

echo "== Subindo as stacks (${MUTATION:+mutação: $MUTATION})"
if ! timeout 175 "${COMPOSE_FINAL[@]}" up --build -d --wait >/dev/null 2>"$TMP/final.err"; then
  echo "erro: a stack final não ficou saudável" >&2; sed 's/^/  | /' "$TMP/final.err" >&2; exit 1
fi
scripts/export-ca.sh "$CA" >/dev/null 2>&1 || { echo "erro: não foi possível exportar a CA local" >&2; exit 1; }
if ! timeout 175 scripts/compare/run-original.sh >"$TMP/orig.log" 2>&1; then
  echo "erro: a stack do original não subiu" >&2; sed 's/^/  | /' "$TMP/orig.log" >&2; exit 1
fi
# Os `docker compose exec` no original precisam das variáveis que o
# original.compose.yml exige (interpolação); run-original.sh as gravou.
[ -f .cache/orig-secrets-path ] && { set -a; . "$(cat .cache/orig-secrets-path)"; set +a; }

# Recria o backend para zerar o rate limit em memória (reexecuções): sem
# isso, o 429 de uma execução anterior barraria o login dos ataques.
if ! "${COMPOSE_FINAL[@]}" up -d --force-recreate --wait --wait-timeout 60 backend >/dev/null 2>"$TMP/recreate.err"; then
  echo "erro: não foi possível recriar o backend (reset do rate limit). Log:" >&2
  sed 's/^/  | /' "$TMP/recreate.err" >&2
  exit 1
fi

# ---------- Ataques HTTP/WebSocket (itens 2–11h), via cliente Node ----------
echo "== Ataques HTTP/WebSocket"
CFG="$TMP/cfg.json"
printf '{"original":{"api":"%s"},"final":{"api":"%s","ws":"%s","origin":"%s","caPath":"%s"}}' \
  "$ORIG_API" "$FINAL_API" "$FINAL_WS" "$FINAL_ORIGIN" "$CA" >"$CFG"
NODE_RC=0
node attacks/matrix.js <"$CFG" >"$TMP/node.json" 2>"$TMP/node.err" || NODE_RC=$?
if [ "$NODE_RC" = 3 ]; then
  echo "TRAVA acionada pelo cliente de ataque (alvo não-local). Saída 3." >&2
  sed 's/^/  | /' "$TMP/node.err" >&2
  exit 3
fi
if [ "$NODE_RC" != 0 ] || [ ! -s "$TMP/node.json" ]; then
  echo "erro: o cliente de ataque falhou (rc=$NODE_RC)" >&2; sed 's/^/  | /' "$TMP/node.err" >&2; exit 1
fi
# As linhas do node já vêm no formato final; converte o array em JSONL.
node -e 'for (const r of JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))) process.stdout.write(JSON.stringify(r)+"\n")' "$TMP/node.json" >>"$ROWS"

# ---------- Item 7: banco legível ----------
echo "== Banco de dados"
ORIG_MSGS="$(psql_orig -c "SELECT count(*) FROM messages WHERE message LIKE 'SEGREDO-ORIG-%'" 2>/dev/null | tr -d '[:space:]')"
ORIG_SAMPLE="$(psql_orig -c "SELECT message FROM messages WHERE message LIKE 'SEGREDO-ORIG-%' LIMIT 1" 2>/dev/null | tr -d '\r')"
if [ "${ORIG_MSGS:-0}" -ge 1 ] 2>/dev/null; then
  emit 7 "Banco legível (texto claro)" original vulneravel vulneravel \
    "a mensagem forjada aparece em claro na coluna messages.message" "mensagens em claro=${ORIG_MSGS}, exemplo=${ORIG_SAMPLE:0:24}…"
else
  emit 7 "Banco legível (texto claro)" original vulneravel inconclusivo "sem mensagem de teste no banco do original" "count=${ORIG_MSGS:-?}"
fi
NAME_ENV="$(psql_final -c "SELECT count(*) FROM information_schema.columns WHERE table_name='rooms' AND column_name='name_env'" 2>/dev/null)"
NAME_PLAIN="$(psql_final -c "SELECT count(*) FROM information_schema.columns WHERE table_name='rooms' AND column_name='name'" 2>/dev/null)"
CHK="$(psql_final -c "SELECT count(*) FROM pg_constraint WHERE conrelid='messages'::regclass AND contype='c' AND pg_get_constraintdef(oid) LIKE '%\"v\":2%'" 2>/dev/null)"
if [ "${NAME_ENV:-0}" = 1 ] && [ "${NAME_PLAIN:-0}" = 0 ] && [ "${CHK:-0}" -ge 1 ] 2>/dev/null; then
  emit 7 "Banco legível (texto claro)" final bloqueado bloqueado \
    "schema força envelope cifrado (CHECK) e nome cifrado (name_env); dados vivos em verify-e2ee.sh" \
    "rooms.name_env=${NAME_ENV}, rooms.name=${NAME_PLAIN}, messages CHECK envelope=${CHK}"
else
  emit 7 "Banco legível (texto claro)" final bloqueado inconclusivo "não foi possível confirmar o schema final" "name_env=${NAME_ENV:-?} name=${NAME_PLAIN:-?} check=${CHK:-?}"
fi

# ---------- Item 11 (TLS): versões aceitas ----------
echo "== TLS"
if echo | timeout 5 openssl s_client -connect 127.0.0.1:18000 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
  emit 11t "TLS e versões" original vulneravel bloqueado "porta do original respondeu TLS (inesperado)" "s_client obteve certificado"
else
  emit 11t "TLS e versões" original vulneravel vulneravel "a porta do original fala HTTP em claro (sem TLS)" "s_client não negociou TLS em 127.0.0.1:18000"
fi
tls_ok() { echo | timeout 6 openssl s_client -connect "$FINAL_HOST:443" -servername "$FINAL_HOST" -CAfile "$CA" "$1" 2>/dev/null | grep -q "Verify return code: 0"; }
tls_refused() { ! echo | timeout 6 openssl s_client -connect "$FINAL_HOST:443" -servername "$FINAL_HOST" -CAfile "$CA" "$1" 2>/dev/null | grep -q "BEGIN CERTIFICATE"; }
if tls_refused -tls1_1 && tls_ok -tls1_2 && tls_ok -tls1_3; then
  emit 11t "TLS e versões" final bloqueado bloqueado "TLS 1.2 e 1.3 aceitos; 1.1 recusado" "tls1_1=recusado tls1_2=ok tls1_3=ok"
else
  emit 11t "TLS e versões" final bloqueado inconclusivo "negociação TLS fora do esperado" "verifique o Caddyfile"
fi

# ---------- Item 1: escuta de rede (capturas comparativas, A4) ----------
echo "== Escuta de rede (capturas)"
# Captura em background e guarda o PID em $SNIFF_PID. NÃO usar via $(...):
# dumpcap precisa ser filho do shell principal para o `wait` funcionar.
start_sniff() { # start_sniff IFACE FILTRO SEGUNDOS ARQUIVO
  dumpcap -q -i "$1" -f "$2" -a "duration:$3" -w "$4" 2>"$4.err" &
  SNIFF_PID=$!
}
can_sniff() { dumpcap -D 2>/dev/null | grep -qw "$1"; }

MARK_PW="SENHA-SNIFF-$(openssl rand -hex 6)"
MARK_MSG="MSG-SNIFF-$(openssl rand -hex 6)"
SNF_EMAIL="snf-$(date +%s)@example.invalid"

# Interface de captura (loopback; "any" como alternativa).
IFACE=lo; can_sniff lo || IFACE=any
SNIFFABLE=0; { can_sniff lo || can_sniff any; } && SNIFFABLE=1

# (1a) Original: o tráfego cliente→127.0.0.1:18000 passa em claro no loopback.
if [ "$SNIFFABLE" = 1 ]; then
  CAP_ORIG="$OUT/sniff-original.pcapng"
  start_sniff "$IFACE" "tcp port 18000" 8 "$CAP_ORIG"; sleep 1.5
  curl -s --max-time 3 -o /dev/null -H 'Content-Type: application/json' -d "{\"email\":\"$SNF_EMAIL\",\"password\":\"$MARK_PW\",\"name\":\"snf\"}" "$ORIG_API/register" || true
  sleep 0.3
  RID=$(curl -s --max-time 3 -H 'Content-Type: application/json' -d '{"name":"snf-room"}' "$ORIG_API/createRoom" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{try{const r=JSON.parse(d);process.stdout.write(String(Array.isArray(r)?r[0].id:r.id))}catch{process.stdout.write("")}})')
  curl -s --max-time 3 -o /dev/null -H 'Content-Type: application/json' -d "{\"room\":{\"id\":${RID:-1}},\"user\":{\"id\":1},\"message\":\"$MARK_MSG\"}" "$ORIG_API/messages" || true
  wait "$SNIFF_PID" 2>/dev/null
  tshark -r "$CAP_ORIG" -d tcp.port==18000,http -T fields -e text 2>/dev/null >"$TMP/cap-orig.txt"
  # HTTP em claro: o marcador está nos BYTES do pacote (find-plaintext lê o
  # arquivo cru, além da extração de texto).
  PW_O=$(cat "$CAP_ORIG" "$TMP/cap-orig.txt" | node scripts/lib/find-plaintext.js "$MARK_PW" >/dev/null 2>&1; echo $?)
  MS_O=$(cat "$CAP_ORIG" "$TMP/cap-orig.txt" | node scripts/lib/find-plaintext.js "$MARK_MSG" >/dev/null 2>&1; echo $?)
  if [ "$PW_O" = 0 ] && [ "$MS_O" = 0 ]; then
    emit 1 "Escuta de rede (sniffing)" original vulneravel vulneravel "senha e mensagem aparecem em claro na captura" "senha=em claro, mensagem=em claro ($CAP_ORIG)"
  else
    emit 1 "Escuta de rede (sniffing)" original vulneravel inconclusivo "não foi possível achar os marcadores na captura do original" "pw_rc=$PW_O msg_rc=$MS_O"
  fi
else
  emit 1 "Escuta de rede (sniffing)" original vulneravel inconclusivo "dumpcap não captura loopback nesta sessão" ""
fi

# (1b) Final externo: loopback na 443 (o que um observador da rede vê).
if [ "$SNIFFABLE" = 1 ]; then
  CAP_FINAL="$OUT/sniff-final-externo.pcapng"
  start_sniff "$IFACE" "tcp port 443" 8 "$CAP_FINAL"; sleep 1.5
  # Faz o login com a senha-marcador e EXIGE que a requisição tenha chegado
  # ao servidor (resposta HTTP real) DENTRO da janela de captura. Sem essa
  # prova, "senha ausente" seria falso: a senha poderia nunca ter trafegado
  # (CA errada, backend fora, login fora da janela) e só os handshakes
  # entrariam na captura. Guarda o maior status visto.
  LOGIN_STATUS=0
  for _ in 1 2 3; do
    st=$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' --cacert "$CA" -H 'Content-Type: application/json' -H "Origin: $FINAL_ORIGIN" \
      -d "{\"email\":\"$SNF_EMAIL\",\"password\":\"$MARK_PW\"}" "$FINAL_API/login" 2>/dev/null || echo 000)
    # 200 (ok), 401 (senha errada) ou 429 (limite) provam que os BYTES da
    # senha trafegaram (cifrados) até o servidor.
    case "$st" in 200|401|429) LOGIN_STATUS=$st ;; esac
  done
  wait "$SNIFF_PID" 2>/dev/null
  tshark -r "$CAP_FINAL" -T fields -e data -e text 2>/dev/null >"$TMP/cap-final.txt"
  # Procura nos BYTES crus da captura (prova mais forte da AUSÊNCIA): com TLS
  # a senha não pode aparecer nem no texto nem nos bytes.
  PW_F=$(cat "$CAP_FINAL" "$TMP/cap-final.txt" | node scripts/lib/find-plaintext.js "$MARK_PW" >/dev/null 2>&1; echo $?)
  # Autoteste do detector: ele ACHA a senha num canal em claro (senão PW_F=10
  # seria um bug do detector, não ausência real).
  SELFTEST=$(printf '%s' "$MARK_PW" | node scripts/lib/find-plaintext.js "$MARK_PW" >/dev/null 2>&1; echo $?)
  PKTS=$(tshark -r "$CAP_FINAL" 2>/dev/null | wc -l)
  if [ "$LOGIN_STATUS" = 0 ] || [ "$SELFTEST" != 0 ]; then
    emit 1 "Escuta de rede (sniffing), externo 443" final bloqueado inconclusivo "o login com a senha não chegou ao servidor na janela (status=$LOGIN_STATUS) ou o detector falhou (selfteste=$SELFTEST): sem isso 'ausente' não prova nada" "pacotes=$PKTS"
  elif [ "$PW_F" = 10 ] && [ "${PKTS:-0}" -gt 0 ]; then
    emit 1 "Escuta de rede (sniffing), externo 443" final bloqueado bloqueado "a senha trafegou (login respondeu $LOGIN_STATUS) e NÃO aparece nos $PKTS pacotes: o TLS cifra na borda" "pacotes=$PKTS, senha=ausente, login=$LOGIN_STATUS ($CAP_FINAL)"
  elif [ "${PKTS:-0}" = 0 ]; then
    emit 1 "Escuta de rede (sniffing), externo 443" final bloqueado inconclusivo "a captura ficou vazia (0 pacotes)" "pacotes=0"
  elif [ "$PW_F" = 0 ]; then
    emit 1 "Escuta de rede (sniffing), externo 443" final bloqueado vulneravel "a senha apareceu em claro na 443 (NÃO esperado)" "pacotes=$PKTS"
  else
    emit 1 "Escuta de rede (sniffing), externo 443" final bloqueado inconclusivo "detector falhou" "rc=$PW_F pacotes=$PKTS"
  fi
else
  emit 1 "Escuta de rede (sniffing), externo 443" final bloqueado inconclusivo "dumpcap não captura loopback nesta sessão" ""
fi

# ---------- Monta a matriz, assere e imprime ----------
node scripts/compare/render-matrix.js "$ROWS" "$OUT/matriz.json" "$OUT/matriz.md" "$MUTATION"
RENDER_RC=$?
echo
cat "$OUT/matriz.md"
echo
echo "evidências em $OUT/ (capturas e matriz não vão para o git)"
exit "$RENDER_RC"
