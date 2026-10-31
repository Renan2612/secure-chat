# Etapa 6 — andamento

Plano: [`plano-etapa6.md`](plano-etapa6.md). Para retomar: ler este arquivo e o plano.

## Parte A — comparação antes e depois

Feito:
- [x] Clone do original fixado no SHA `873df2cd…` em `.cache/` (gitignored); `.gitignore` cobre `.cache/` e `evidencias/`; SHA e ajustes de boot em `docs/09`
- [x] A1 `scripts/compare/run-original.sh` + `original.compose.yml` + `original.Dockerfile` + `stop-original.sh`: sobe API (127.0.0.1:18000) e Postgres (sem porta) do original, projeto próprio, trap de limpeza com `down -v` só do projeto do original
- [x] A2 cliente de ataque em `attacks/` (package próprio, versões exatas, só `socket.io-client` e `ws`, `npm ci`, 0 vulnerabilidades, lockfile só npmjs)
- [x] A3 `attack-matrix.sh` roda os 11 ataques contra original (vulnerável) e final (bloqueado), com asserção por alvo, controle positivo e saída 1 se alguma defesa da FINAL falhar; `render-matrix.js` grava `matriz.{md,json}`
- [x] Trava de alvo local (`lib-local-guard.sh`, também em `matrix.js`): aborta se o alvo não for 127.0.0.1/localhost
- [x] A4 capturas comparativas: `evidencias/etapa6/sniff-original.pcapng` (28 pacotes, senha+mensagem em claro) e `sniff-final-externo.pcapng` (63 pacotes, senha ausente), não commitadas
- [x] A5 mutações: (i) `MUTATION=skip-defense` desliga a autorização por sala (flag `TEST_SKIP_ROOM_MEMBER`, nunca ativa por padrão) → matriz sai com 1 (#3 quebrada); (ii) `MUTATION=nonlocal-target` → trava aborta com saída 3
- [x] Matriz final: 13/13 defesas da versão final confirmadas; original vulnerável em todos os itens aplicáveis. Saída 0
- [x] Stack do original derrubada; banco final sem usuários de teste

Resultado da matriz (resumo): todos os ataques que funcionam no original
(sniffing, falsificar identidade, ler sala alheia, ouvinte anônimo, vazamento
de hash, entrar sem convite, banco em claro, CSRF, CSWSH, força bruta, flags
de cookie, HSTS/CSP, TLS) são **bloqueados** na stack final.

Decisões tomadas sozinho (registradas):
- Imagem efêmera do original (não vendorizada) em vez de montar o clone
  gravável — mantém o `.cache` intacto e evita compilar deps nativas.
- A matriz recria o backend da final antes dos ataques, para zerar o rate
  limit em memória entre reexecuções (o plano já prevê "429: reinicie o backend").
- Item 7 (banco) na FINAL é checado pelo schema (CHECK de envelope, `name_env`);
  os dados vivos cifrados já são provados por `verify-e2ee.sh`.
- Item 8b (CSWSH) no original é reportado conforme observado: o `socket.io`
  aplica o CORS dele no handshake.

## Parte B — implantação e endurecimento

Feito:
- [x] Acréscimo: flags SÓ DE TESTE (`TEST_SKIP_ROOM_MEMBER`, `E2EE_TEST_*`) só valem em `NODE_ENV=test`; backend RECUSA subir em `NODE_ENV=production` com qualquer uma definida (`backend/config/testFlags.js`, `assertSafe` no `createApp`); teste em `backend/tests/testFlags.test.js`; os overrides que as usam passaram a subir em `NODE_ENV=test`
- [x] B1 endurecimento no `docker-compose.yml`: raiz somente leitura + tmpfs, `cap_drop ALL` (proxy readiciona só NET_BIND_SERVICE; db só as capacidades para baixar a root→postgres), `no-new-privileges`, backend como usuário `node`, `mem_limit`/`cpus`/`pids_limit`. Stack segue saudável e servindo 200
- [x] B2 perfil de produção: `docker-compose.prod.yml` (portas 80/443 em 0.0.0.0, só neste perfil) + `proxy/Caddyfile.prod` (domínio por `DOMAIN`, Let's Encrypt por `ACME_EMAIL`, HSTS com preload). Validado por `docker compose config` e `caddy validate`; NÃO subido na internet
- [x] B3 `deploy/`: `nftables.conf` e `ufw.sh` (só 80/443 + SSH restrito), `check-firewall.sh` (confere 8000/5432 fechadas, sem sudo), `wireguard.conf.example` (só placeholders), `host-checklist.md` (updates, SSH, backups cifrados com retenção, rotação de segredos)
- [x] B4 `.github/workflows/ci.yml`: push/PR, `permissions: contents: read`, sem secrets, sem `pull_request_target`; Postgres como serviço; `npm ci`/`npm test`/`npm audit --omit=dev` (backend e frontend); `verify-frontend.sh` com `NO_PROXY_CHECK` (sem Docker); checagem de lockfiles. Actions fixadas por tag (limite dos SHAs em docs/08). NÃO executado
- [x] B5 `scripts/verify-hardening.sh`: confere B1 por `docker inspect`, 8000/5432 não publicadas, só 127.0.0.1:80/443 no dev, e a sintaxe do perfil de produção; mutação `publish-db` sai com 1
- [x] verify-hardening.sh, verify-tls.sh e verify-e2ee.sh: saída 0 cada

Decisões tomadas sozinho (registradas):
- As flags de teste passaram a exigir `NODE_ENV=test`; por isso os overrides de `verify-e2ee.sh` e a mutação (i) do `attack-matrix.sh` agora sobem o backend em `NODE_ENV=test` (onde as flags valem). Efeito colateral aceito: nesse modo o cookie de sessão perde o `Secure` (a mutação (i) pode marcar também o item de cookie).
- `mem_limit`/`cpus`/`pids_limit` de topo em vez de `deploy.resources` (o Compose v2 fora de swarm honra os de topo e recusa misturar com `pids_limit`).
- Limites: db 512M, backend 256M, proxy 128M, frontend 256M; pids 256 (64 no frontend).

Pendente:
- [ ] Parte C (docs 08/09, atualizar 00/01/README, fechamento com review + simplifier)
