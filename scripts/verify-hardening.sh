#!/usr/bin/env bash
# Provas do endurecimento (Etapa 6, B5). Sem sudo. Confere, na stack de
# DESENVOLVIMENTO no ar:
#   - o que cada serviço de fato aplicou (docker inspect): raiz somente
#     leitura, cap_drop ALL, no-new-privileges, limites de PIDs e memória, e
#     o backend sem rodar como root;
#   - que as portas 8000 (backend) e 5432 (Postgres) NÃO estão publicadas;
#   - que só 127.0.0.1:80 e :443 são publicadas (o proxy), nada em 0.0.0.0;
#   - que o perfil de PRODUÇÃO é sintaticamente válido (docker compose config
#     + caddy validate), sem subir nada.
# Mutação: MUTATION=publish-db publica a porta do banco → o script sai com 1.
set -uo pipefail
umask 077
cd "$(dirname "$0")/.."

COMPOSE=(docker compose --env-file backend/.env)
MUTATION="${MUTATION:-}"
EXTRA=()
if [ "$MUTATION" = publish-db ]; then EXTRA=(-f docker-compose.yml -f scripts/compare/mutations-publish-db.yml); fi

FAILS=0
ok() { printf '  OK     %s\n' "$*"; }
ko() { printf '  FALHA  %s\n' "$*"; FAILS=$((FAILS + 1)); }
check() { local d="$1"; shift; if "$@"; then ok "$d"; else ko "$d"; fi; }
section() { printf '\n== %s\n' "$*"; }

command -v docker >/dev/null || { echo "erro: docker não encontrado" >&2; exit 2; }
TMP_ERR="$(mktemp)"; trap 'rm -f "$TMP_ERR"' EXIT

if [ -n "$MUTATION" ]; then
  echo "  (MUTAÇÃO ATIVA: $MUTATION — esperado: falhar)"
  # Recria a stack com a mutação para que a inspeção veja o estado mutado.
  # Fatal se não aplicar: sem o estado mutado, a prova da mutação viraria um
  # falso-negativo (o db ficaria sem a porta e o script "passaria").
  if ! timeout 120 "${COMPOSE[@]}" "${EXTRA[@]}" up -d --force-recreate --wait >/dev/null 2>"$TMP_ERR"; then
    echo "erro: não foi possível aplicar a mutação $MUTATION (a prova dela não pôde ser exercida)" >&2
    sed 's/^/  | /' "$TMP_ERR" >&2 2>/dev/null || true
    exit 2
  fi
fi

if [ -z "$("${COMPOSE[@]}" ps -q db 2>/dev/null)" ]; then
  echo "erro: a stack de desenvolvimento não está no ar (docker compose --env-file backend/.env up -d)" >&2
  exit 2
fi

insp() { docker inspect -f "$2" "$(${COMPOSE[@]} ps -q "$1")" 2>/dev/null; }

section "Endurecimento dos contêineres (docker inspect)"
for svc in db backend proxy; do
  ro="$(insp "$svc" '{{.HostConfig.ReadonlyRootfs}}')"
  nnp="$(insp "$svc" '{{.HostConfig.SecurityOpt}}')"
  pids="$(insp "$svc" '{{.HostConfig.PidsLimit}}')"
  mem="$(insp "$svc" '{{.HostConfig.Memory}}')"
  capdrop="$(insp "$svc" '{{.HostConfig.CapDrop}}')"
  check "$svc: raiz somente leitura" test "$ro" = "true"
  check "$svc: no-new-privileges" bash -c "[[ '$nnp' == *no-new-privileges:true* ]]"
  check "$svc: cap_drop inclui ALL" bash -c "[[ '$capdrop' == *ALL* ]]"
  check "$svc: pids_limit > 0 (${pids:-?})" bash -c "[ \"${pids:-0}\" -gt 0 ]"
  check "$svc: limite de memória definido (${mem:-?})" bash -c "[ \"${mem:-0}\" -gt 0 ]"
done
BACKEND_USER="$(insp backend '{{.Config.User}}')"
check "backend não roda como root (user=${BACKEND_USER:-vazio})" bash -c "[ -n '$BACKEND_USER' ] && [ '$BACKEND_USER' != root ] && [ '$BACKEND_USER' != 0 ]"
PROXY_CAPADD="$(insp proxy '{{.HostConfig.CapAdd}}')"
check "proxy readiciona só NET_BIND_SERVICE" bash -c "[[ '$PROXY_CAPADD' == *NET_BIND_SERVICE* ]]"

section "Portas publicadas no host"
# Mapa de portas publicadas de todos os serviços do projeto.
PORTS="$("${COMPOSE[@]}" ps --format '{{.Publishers}}' 2>/dev/null)"
PUB="$(docker ps --filter "label=com.docker.compose.project=$(basename "$PWD")" --format '{{.Ports}}' 2>/dev/null)"
# Backend e banco não podem estar publicados.
no_port() { # no_port SERVICO PORTA_INTERNA
  local id; id="$("${COMPOSE[@]}" ps -q "$1")"
  [ -n "$id" ] || return 0
  local b; b="$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$id")"
  [ "$b" = "{}" ] || [ "$b" = "null" ]
}
check "backend sem porta publicada" no_port backend
check "db sem porta publicada" no_port db
# Proxy: só 127.0.0.1:80 e :443.
PROXY_BIND="$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$("${COMPOSE[@]}" ps -q proxy)" 2>/dev/null)"
proxy_only_loopback() {
  [[ "$PROXY_BIND" == *'"443/tcp":[{"HostIp":"127.0.0.1","HostPort":"443"}]'* ]] &&
    [[ "$PROXY_BIND" == *'"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"80"}]'* ]] &&
    [[ "$PROXY_BIND" != *'"HostIp":"0.0.0.0"'* ]] && [[ "$PROXY_BIND" != *'"HostIp":""'* ]]
}
check "proxy publica só em 127.0.0.1 (80 e 443), nada em 0.0.0.0" proxy_only_loopback
# As portas internas 8000/5432 não aparecem como publicadas em lugar nenhum.
check "nenhuma publicação de 8000 ou 5432 no host" bash -c "! echo '$PUB' | grep -qE '(:8000|:5432)->'"

section "Perfil de produção (sintaxe, sem subir)"
# Monta o compose do perfil de produção (as variáveis são só para a
# interpolação da sintaxe; nada sobe).
prod_config() {
  DOMAIN=chat.exemplo.com ACME_EMAIL=ops@exemplo.com \
    "${COMPOSE[@]}" -f docker-compose.yml -f docker-compose.prod.yml config
}
prod_config_ok() { prod_config >/dev/null 2>&1; }
check "docker compose config do perfil de produção é válido" prod_config_ok
# O perfil de produção publica em 0.0.0.0 (e não em 127.0.0.1).
prod_ports_public() {
  # Confere no bloco de portas do proxy: existe published "443" E nenhum
  # host_ip 127.0.0.1 ali (ausência de 127.0.0.1 no arquivo inteiro não
  # bastaria — poderia não publicar nada, ou ter 127.0.0.1 noutro lugar).
  local cfg; cfg="$(prod_config 2>/dev/null)"
  local ports; ports="$(printf '%s' "$cfg" | sed -n '/^    ports:/,/^    [a-z]/p')"
  printf '%s' "$ports" | grep -q 'published: "443"' &&
    printf '%s' "$ports" | grep -q 'published: "80"' &&
    ! printf '%s' "$ports" | grep -q '127.0.0.1'
}
check "produção publica em 0.0.0.0 (sem 127.0.0.1)" prod_ports_public
caddy_prod_ok() {
  timeout 40 docker run --rm -e DOMAIN=chat.exemplo.com -e ACME_EMAIL=ops@exemplo.com \
    -v "$PWD/proxy/Caddyfile.prod:/etc/caddy/Caddyfile:ro" \
    caddy:2.11.7-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f \
    caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1
}
check "caddy validate do Caddyfile.prod" caddy_prod_ok

echo
if [ "$FAILS" -eq 0 ]; then echo "RESULTADO: todas as provas passaram"; else echo "RESULTADO: $FAILS prova(s) falharam"; fi
[ "$FAILS" -eq 0 ]
