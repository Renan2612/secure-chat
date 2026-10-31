# Checklist de endurecimento do HOST (Etapa 6, B3)

Itens que o operador aplica no servidor de produção (fora do escopo
automatizável deste repositório). Nenhum é executado aqui.

## Sistema
- [ ] Atualizações de segurança automáticas (`unattended-upgrades` no
      Debian/Ubuntu, ou `dnf-automatic`), com reinício agendado.
- [ ] Relógio sincronizado (NTP): a expiração das mensagens e os
      certificados dependem disso.

## Acesso
- [ ] SSH **sem senha**: só chave pública (`PasswordAuthentication no`,
      `PermitRootLogin no`, `KbdInteractiveAuthentication no`).
- [ ] SSH restrito à rede de administração pelo firewall
      (`deploy/nftables.conf` ou `deploy/ufw.sh`), ou acessível só pela VPN
      (`deploy/wireguard.conf.example`).
- [ ] Confirmar com `deploy/check-firewall.sh` que só 80/443 respondem e que
      8000 e 5432 estão fechadas.

## Segredos
- [ ] `backend/.env` (com `DB_PASSWORD`, `SESSION_SECRET`) **fora do git** e
      com permissão 600; nunca em imagem nem em log.
- [ ] `SESSION_SECRET` com ≥ 32 caracteres aleatórios. Rotação: gere um novo,
      mova o atual para `SESSION_SECRET_PREVIOUS` (o backend aceita os dois
      por uma janela, para não deslogar todo mundo) e remova o antigo depois.
- [ ] Rotacionar `DB_PASSWORD` periodicamente (atualizar no `.env` e no banco).

## Backups
- [ ] Backup do volume do Postgres **cifrado em repouso** (ex.: `pg_dump` →
      `age`/`gpg`), enviado para fora do host.
- [ ] Política de retenção definida (ex.: diário por 7 dias, semanal por 4,
      mensal por 6) e **restauração testada**.
- [ ] Lembrar: o backup guarda só o envelope cifrado das mensagens e o nome
      cifrado das salas; sem as chaves dos clientes, o conteúdo não abre
      (docs/05, docs/06).

## Contêineres
- [ ] Já aplicado no `docker-compose.yml`: raiz somente leitura, `cap_drop`,
      `no-new-privileges`, usuário sem privilégios, limites de memória/CPU/PIDs.
      Conferir com `scripts/verify-hardening.sh`.
