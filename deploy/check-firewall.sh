#!/usr/bin/env bash
# Confere, DEPOIS de aplicar o firewall, que só 80/443 estão expostas e que
# 8000 (backend) e 5432 (Postgres) estão fechadas (Etapa 6, B3). Pode rodar
# sem sudo. Não altera nada. Rode a partir de outra máquina para testar de
# fora (HOST=ip-do-servidor), ou localmente (HOST=127.0.0.1).
set -uo pipefail
HOST="${HOST:-127.0.0.1}"
echo "== Portas em escuta no host (ss -ltn):"
command -v ss >/dev/null && ss -ltn || echo "(ss indisponível)"
echo
fail=0
probe() { # probe PORTA esperado(aberta|fechada)
  if timeout 3 bash -c "</dev/tcp/$HOST/$1" 2>/dev/null; then estado=aberta; else estado=fechada; fi
  if [ "$estado" = "$2" ]; then echo "  OK    $HOST:$1 $estado (esperado $2)"; else echo "  FALHA $HOST:$1 $estado (esperado $2)"; fail=1; fi
}
probe 443 aberta
probe 8000 fechada
probe 5432 fechada
exit "$fail"
