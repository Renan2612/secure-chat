# Secure Chat — Projeto de Redes

Chat em tempo real com foco em segurança e privacidade, desenvolvido para a
disciplina de Redes (Engenharia de Software). O backend parte de um fork
saneado de [asafebxd/MessageWebApp](https://github.com/asafebxd/MessageWebApp)
(ver atribuição abaixo).

## Status

🚧 Em desenvolvimento. Etapas concluídas:

- [x] **Etapa 0** — Modelo de ameaças ([`docs/00-modelo-ameacas.md`](docs/00-modelo-ameacas.md))
- [x] **Etapa 1** — Saneamento do projeto base ([`docs/01-baseline-seguranca.md`](docs/01-baseline-seguranca.md))
- [x] **Etapa 2** — Autenticação e autorização ([`docs/02-autenticacao-autorizacao.md`](docs/02-autenticacao-autorizacao.md))
- [x] **Etapa 3** — Camada de comunicação: protocolo próprio sobre WebSocket ([`docs/03-protocolo.md`](docs/03-protocolo.md))
- [x] **Etapa 4a** — TLS, proxy reverso (Caddy) e origem única ([`docs/04-tls-e-proxy.md`](docs/04-tls-e-proxy.md))
- [ ] Etapa 4b — Criptografia ponta a ponta (E2EE)
- [ ] Etapa 5 — Privacidade adicional
- [ ] Etapa 6 — Infraestrutura e validação
- [ ] Etapa 7 — Entrega

> **Importante**: desde a Etapa 4a, tudo passa por uma **origem única
> `https://localhost`**, servida pelo Caddy, que termina o TLS: página em
> `/`, API em `/api/*`, tempo real em `wss://localhost/ws`. Backend e banco
> não publicam portas. **O TLS termina no proxy**: proxy, backend e banco
> ainda veem senha e mensagens em claro, e as mensagens ficam em claro no
> banco. Só a criptografia ponta a ponta (Etapa 4b) resolve isso. O
> `POST /messages` foi removido na Etapa 3; o envio é só pelo WebSocket
> ([`docs/03-protocolo.md`](docs/03-protocolo.md) §10).

## Estrutura

```
secure-chat/
├── docs/
│   ├── 00-modelo-ameacas.md          # Etapa 0
│   ├── 01-baseline-seguranca.md      # Etapa 1 — registro antes/depois
│   ├── 02-autenticacao-autorizacao.md # Etapa 2
│   ├── 03-protocolo.md           # Etapa 3 — especificação do protocolo
│   └── 04-tls-e-proxy.md         # Etapa 4a — TLS, proxy e origem única
├── proxy/
│   ├── Caddyfile                 # proxy reverso + política TLS
│   └── site/index.html           # página estática provisória (/)
├── scripts/
│   ├── export-ca.sh              # exporta a raiz da CA local do Caddy
│   └── verify-tls.sh             # provas da Etapa 4a contra a stack no ar
├── backend/
│   ├── server.js                  # ponto de entrada (sobe o createServer)
│   ├── createServer.js            # HTTP (Express) + tempo real (/ws), mesma sessão
│   ├── app.js                     # montagem do Express (rotas, middlewares)
│   ├── realtime/                  # protocolo sobre WebSocket: upgrade, conexão, pacotes, salas
│   ├── db.js                      # pool único de conexão ao Postgres
│   ├── config/session.js          # sessão no servidor (express-session + Postgres)
│   ├── middleware/                # requireAuth, requireRoomMember, validate, errorHandler
│   ├── validation/schemas.js      # schemas zod de cada rota
│   ├── routes/
│   ├── helpers/
│   ├── tests/                     # testes de ataque (jest + supertest + ws)
│   ├── tools/ws-client.js         # cliente de referência do protocolo (CLI)
│   ├── database/
│   │   ├── migrations.sql
│   │   └── seeds.sql
│   ├── .env.example
│   ├── Dockerfile
│   └── package.json
├── docker-compose.yml             # proxy (único publicado), backend e banco
├── docker-compose.test.yml        # Postgres descartável para os testes
└── .gitignore
```

O frontend React do projeto original ainda não foi incorporado nem
auditado; ao incorporá-lo, ele precisa seguir o contrato da
[Etapa 3](docs/03-protocolo.md#10-mudanças-de-contrato-para-o-frontend).

## Como rodar

### Opção 1: Docker (recomendado)

```bash
cp backend/.env.example backend/.env
# edite backend/.env com valores reais — em especial SESSION_SECRET
# (mínimo 32 caracteres; o servidor não sobe com o placeholder) e DB_PASSWORD
docker compose --env-file backend/.env up --build
```

O `--env-file` faz o banco nascer com a mesma senha que o backend usa
(sem ele, o compose recusa subir: `DB_PASSWORD` é obrigatório). O único
serviço publicado é o **proxy**, em `127.0.0.1:80` (redireciona) e
`127.0.0.1:443`. Backend e banco ficam só na rede interna do compose, e o
backend roda como usuário sem privilégios (`node`).

O certificado de `https://localhost` vem da **CA local do Caddy**. Exporte a
raiz e use-a nos clientes (a verificação nunca é desligada):

```bash
scripts/export-ca.sh                                   # → certs/caddy-local-root.crt
curl --cacert certs/caddy-local-root.crt https://localhost/api/health   # {"status":"ok"}
scripts/verify-tls.sh                                  # provas de TLS e da origem única
```

Para testar o chat pelo terminal (com usuário e sala já criados):

```bash
CHAT_PASSWORD='sua-senha' node backend/tools/ws-client.js --server https://localhost/api \
  --ca certs/caddy-local-root.crt --origin https://localhost --email voce@example.com --room 1
```

Para derrubar: `docker compose --env-file backend/.env down` (sem `-v`,
preserva o banco e a CA local).

> Vindo de uma etapa anterior? O schema mudou (Etapa 2: tabela de sessões,
> e-mail único; Etapa 3: `messages.message` em TEXT e coluna `cid`) e o
> script de init só roda num volume vazio: recrie com
> `docker compose down -v && docker compose --env-file backend/.env up --build`
> (apaga os dados de desenvolvimento). Se o volume foi criado sem o
> `--env-file`, a senha do banco é a antiga padrão (`troque_esta_senha`) e o
> `/health` responde 503: recrie o volume ou ajuste a senha com
> `ALTER USER` no `psql` do container.

### Opção 2: manual (desenvolvimento, sem TLS)

Requer Node.js ≥ 22 e PostgreSQL rodando localmente. Sobe o backend direto
em `http://localhost:8000`, sem proxy nem TLS: serve só para desenvolvimento
local.

```bash
cd backend
cp .env.example .env
# edite .env
npm install
createdb -U seu_usuario secure_chat
psql -U seu_usuario -d secure_chat -f database/migrations.sql
npm run dev
```

## Testes

Testes de ataque automatizados (jest + supertest, e WebSocket real para o
protocolo) contra um Postgres de teste separado:

```bash
docker compose -f docker-compose.test.yml up -d --wait
cd backend
npm test
```

## Atribuição

Backend baseado em [asafebxd/MessageWebApp](https://github.com/asafebxd/MessageWebApp)
(licença ISC), usado como ponto de partida e reescrito ao longo do projeto
conforme o modelo de ameaças e o roteiro de etapas da disciplina.

## Documentação

- [Modelo de ameaças](docs/00-modelo-ameacas.md)
- [Linha de base de segurança (antes/depois)](docs/01-baseline-seguranca.md)
- [Autenticação e autorização (Etapa 2)](docs/02-autenticacao-autorizacao.md)
- [Protocolo de tempo real (Etapa 3)](docs/03-protocolo.md)
- [TLS, proxy reverso e origem única (Etapa 4a)](docs/04-tls-e-proxy.md)
