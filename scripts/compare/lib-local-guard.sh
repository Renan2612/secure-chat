# Trava de segurança compartilhada (regra da Etapa 6): nenhum ataque pode
# mirar um host que não seja 127.0.0.1 ou localhost. Quem usa define TARGETS
# (lista de URLs/hosts) e chama assert_local_targets; qualquer alvo não-local
# aborta com código 3 ANTES de qualquer ataque. Testado por mutação
# (attack-matrix.sh --self-test e a mutação (ii) do plano).
host_of() { # extrai o host de uma URL ou aceita host puro
  local v="$1"
  v="${v#*://}"      # tira esquema://
  v="${v%%/*}"       # tira /caminho
  v="${v%%\?*}"      # tira ?query
  v="${v##*@}"       # tira user@
  v="${v%:*}"        # tira :porta (hosts sem ':' ficam iguais)
  printf '%s' "$v"
}
is_local_host() {
  case "$(host_of "$1")" in
    127.0.0.1 | localhost | "[::1]" | ::1) return 0 ;;
    *) return 1 ;;
  esac
}
assert_local_targets() { # assert_local_targets alvo...
  local bad=0 t
  for t in "$@"; do
    if ! is_local_host "$t"; then
      printf 'ABORTADO: alvo não-local recusado: %s (só 127.0.0.1/localhost)\n' "$t" >&2
      bad=1
    fi
  done
  [ "$bad" = 0 ] || exit 3
}
