#!/usr/bin/env bash
# Alternativa ao nftables com UFW (Etapa 6, B3) — MODELO, aplique com sudo.
# NÃO é executado por este projeto. Revise o SSH_ADMIN_CIDR antes.
set -euo pipefail
SSH_ADMIN_CIDR="${SSH_ADMIN_CIDR:?defina a sua sub-rede de administração, ex.: 203.0.113.0/24}"

sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
# SSH só da rede de administração (nunca de qualquer lugar).
sudo ufw allow from "$SSH_ADMIN_CIDR" to any port 22 proto tcp
# Serviço público: só o proxy.
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
sudo ufw status verbose
echo "Pronto. Confirme com deploy/check-firewall.sh que 8000 e 5432 estão fechadas."
