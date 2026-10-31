#!/usr/bin/env bash
# Derruba a stack do ORIGINAL e apaga os volumes SÓ do projeto dele
# (secure-chat-original). Nunca toca nos volumes da stack final. Idempotente.
set -uo pipefail
cd "$(dirname "$0")/../.."
docker compose -f scripts/compare/original.compose.yml down -v --remove-orphans >/dev/null 2>&1 || true
echo "(stack do original derrubada; volumes do projeto secure-chat-original removidos)"
