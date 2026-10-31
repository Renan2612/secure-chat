# Etapa 6 — Implantação e endurecimento

Como esta stack é pensada para rodar em produção, o que foi endurecido, e o
que **não** foi testado na internet (e por quê). O endurecimento dos
contêineres é conferido por `scripts/verify-hardening.sh`.

## 1. Topologia

```
            Internet
               │  80/tcp, 443/tcp (só no perfil de produção, em 0.0.0.0)
        ┌──────▼───────┐
        │  proxy (Caddy)│  TLS termina aqui; HSTS, CSP, cabeçalhos
        └──────┬───────┘
      rede "borda" │ (só o proxy)
               │
      rede "interna" (internal: true — sem rota para fora)
        ┌──────┴───────┬───────────────┐
        │              │               │
   ┌────▼────┐   ┌─────▼─────┐    (frontend: builder de uso único;
   │ backend │   │  db (PG)  │     publica o dist num volume e sai)
   │  :8000  │   │  :5432    │
   └─────────┘   └───────────┘
```

- **Único serviço publicado**: o proxy. Backend e banco ficam só na rede
  `interna` (`internal: true`), sem porta no host e sem saída para a internet.
- **Desenvolvimento** (`docker-compose.yml`): o proxy publica 80 e 443 **só
  em `127.0.0.1`**; o TLS usa a CA local do Caddy (`tls internal`).
- **Produção** (`docker-compose.prod.yml` + `proxy/Caddyfile.prod`): o proxy
  publica em `0.0.0.0`, com HTTPS automático (Let's Encrypt/ACME) para
  `DOMAIN`, e-mail em `ACME_EMAIL`.

## 2. Endurecimento dos contêineres (`docker-compose.yml`, B1)

| Serviço | Raiz | Capacidades | Usuário | Limites |
|---|---|---|---|---|
| db (Postgres) | somente leitura + tmpfs (`/tmp`, `/run/postgresql`) | `cap_drop ALL` + só `CHOWN,DAC_OVERRIDE,FOWNER,SETGID,SETUID` (baixar root→postgres) | postgres (via entrypoint) | 512M, 1 CPU, 256 PIDs |
| backend | somente leitura + tmpfs (`/tmp`) | `cap_drop ALL` | **`node`** (sem privilégio) | 256M, 1 CPU, 256 PIDs |
| proxy (Caddy) | somente leitura + tmpfs (`/tmp`); dados em volumes | `cap_drop ALL` + só `NET_BIND_SERVICE` | padrão da imagem | 128M, 1 CPU, 256 PIDs |
| frontend (builder) | somente leitura + tmpfs; sem rede | `cap_drop ALL` | padrão | 256M, 1 CPU, 64 PIDs |

Todos com `no-new-privileges:true` e logs `json-file` com rotação (3 × 1 MB).
Conferência: `scripts/verify-hardening.sh` (inclui a mutação `publish-db`,
que publica a porta do banco e faz o script sair com 1).

> **Nota (`mem_limit`/`cpus`/`pids_limit`):** fora do Swarm, o Compose v2
> honra esses campos de topo (não `deploy.resources`), e recusa misturar
> `pids_limit` com `deploy.resources.limits.pids`.

## 3. Perfil de produção (B2) — validado, NÃO subido

`docker-compose.prod.yml` (override) e `proxy/Caddyfile.prod` trazem domínio
por `DOMAIN`, Let's Encrypt por `ACME_EMAIL` e as portas em `0.0.0.0`. Foram
validados **sem subir na internet**:

```bash
DOMAIN=chat.exemplo.com ACME_EMAIL=ops@exemplo.com \
  docker compose --env-file backend/.env -f docker-compose.yml -f docker-compose.prod.yml config
# e, dentro do contêiner do Caddy:
caddy validate --config /etc/caddy/Caddyfile
```

**HSTS sem `preload` (acréscimo a).** O `Caddyfile.prod` emite
`Strict-Transport-Security: max-age=31536000; includeSubDomains`, **sem**
`preload`. O `preload` inscreve o domínio na lista embutida dos navegadores
e é **difícil de reverter** (tirar o domínio da lista leva semanas/meses):
só se adota de propósito, quando se tem certeza de que todo o domínio e os
subdomínios ficarão em HTTPS para sempre. Por isso ele não entra por padrão;
para adotar, acrescente `; preload` e inscreva o domínio em hstspreload.org.
Nenhuma prova depende do `preload` (o `verify-tls.sh` confere só `max-age` e
`includeSubDomains` no perfil de desenvolvimento).

## 4. Firewall e VPN do host (B3) — MODELOS, nunca aplicados

Os arquivos em `deploy/` são **modelos** que o operador aplica no servidor
com `sudo`. **Nada em `deploy/` foi executado neste projeto** (sem acesso a
um host de produção e sem sudo): não há prova de runtime do firewall nem do
WireGuard, só a revisão da sintaxe e das regras.

- `deploy/nftables.conf` / `deploy/ufw.sh`: entrada negada por padrão; só
  `80/tcp` e `443/tcp` abertos ao mundo; SSH (`22/tcp`) restrito à rede de
  administração (ajustar o CIDR antes de aplicar). As portas 8000 e 5432 não
  escutam no host (contêineres) e ainda assim são negadas pelo firewall
  (segunda barreira).
- `deploy/check-firewall.sh`: depois de aplicar, confere com `ss -ltn` e com
  tentativas de conexão que 443 responde e que 8000/5432 estão fechadas.
  Roda sem sudo; pode ser rodado de outra máquina (`HOST=<ip>`).
- `deploy/wireguard.conf.example`: **só placeholders** — nenhuma chave real,
  nenhum IP real. As chaves são geradas localmente (instruções no arquivo) e
  nunca entram no git.

## 5. Backups e rotação de segredos (checklist em `deploy/host-checklist.md`)

- **Backup** do volume do Postgres **cifrado em repouso** (ex.: `pg_dump` →
  `age`/`gpg`), fora do host, com política de retenção definida e restauração
  testada. O backup guarda só o envelope cifrado das mensagens e o nome
  cifrado das salas: sem as chaves dos clientes, o conteúdo não abre
  (docs/05, docs/06).
- **`SESSION_SECRET`** ≥ 32 caracteres. Rotação sem deslogar todo mundo: o
  novo vira `SESSION_SECRET`, o atual vai para `SESSION_SECRET_PREVIOUS` (o
  backend aceita os dois por uma janela) e o antigo é removido depois.
- **`DB_PASSWORD`** e o `backend/.env` ficam fora do git (600), nunca em
  imagem nem em log.

## 6. Integração contínua (B4)

`.github/workflows/ci.yml` roda em `push` e `pull_request`, com
`permissions: contents: read`, **sem** secrets e **sem**
`pull_request_target`. Sobe o Postgres como serviço e roda `npm ci`,
`npm test` e `npm audit --omit=dev` no backend e no frontend, o
`verify-frontend.sh` sem Docker (`NO_PROXY_CHECK=1`) e a checagem de
lockfiles (só `registry.npmjs.org`). **O workflow não foi executado** aqui.

**Limite — actions fixadas por tag, não por SHA (acréscimo a).** As actions
usam `actions/checkout@v4` e `actions/setup-node@v4` (tag de versão maior).
Uma tag é **mutável**: o dono da action pode reapontá-la para outro commit,
então isto confia no fornecedor. O endurecimento completo é fixar pelo
**SHA** do commit (`actions/checkout@<sha40>`), que é imutável. Não fixei por
SHA porque não consegui confirmar os SHAs com segurança no ambiente desta
entrega; para produção, troque as tags pelos SHAs correspondentes (e um bot
tipo Dependabot para atualizá-los).

## 7. O que NÃO foi testado na internet (e por quê)

| Item | Estado | Por quê |
|---|---|---|
| Let's Encrypt (ACME) | só `caddy validate` + `compose config` | emitir certificado real exige um domínio público e as portas 80/443 expostas; fora do escopo e do ambiente desta entrega |
| Firewall do host (nftables/ufw) | modelo revisado, **não aplicado** | precisa de um host com `sudo`; não há prova de runtime |
| WireGuard | modelo só com placeholders, **não aplicado** | idem; e nenhuma chave/IP real deve entrar no repositório |
| Portas em `0.0.0.0` (produção) | só `compose config` | subir em `0.0.0.0` exporia o serviço; o desenvolvimento fica em `127.0.0.1` |
