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
- [ ] Etapa 3 — Camada de comunicação (protocolo / socket autenticado)
- [ ] Etapa 4 — Criptografia ponta a ponta (E2EE) + TLS
- [ ] Etapa 5 — Privacidade adicional
- [ ] Etapa 6 — Infraestrutura e validação
- [ ] Etapa 7 — Entrega

> **Importante**: a Etapa 2 fechou a API HTTP (sessão no servidor,
> autenticação e autorização por sala, convite com chave), mas o
> **Socket.IO continua sem autenticação e com broadcast global** — quem
> conecta no socket ainda recebe as mensagens de todas as salas. Isso é a
> Etapa 3 e está registrado em
> [`docs/01-baseline-seguranca.md`](docs/01-baseline-seguranca.md).

## Estrutura

```
secure-chat/
├── docs/
│   ├── 00-modelo-ameacas.md          # Etapa 0
│   ├── 01-baseline-seguranca.md      # Etapa 1 — registro antes/depois
│   └── 02-autenticacao-autorizacao.md # Etapa 2
├── backend/
│   ├── server.js                  # HTTP + Socket.IO
│   ├── app.js                     # montagem do Express (rotas, middlewares)
│   ├── db.js                      # pool único de conexão ao Postgres
│   ├── config/session.js          # sessão no servidor (express-session + Postgres)
│   ├── middleware/                # requireAuth, requireRoomMember, validate, errorHandler
│   ├── validation/schemas.js      # schemas zod de cada rota
│   ├── routes/
│   ├── helpers/
│   ├── tests/                     # testes de ataque (jest + supertest)
│   ├── database/
│   │   ├── migrations.sql
│   │   └── seeds.sql
│   ├── .env.example
│   ├── Dockerfile
│   └── package.json
├── docker-compose.yml
├── docker-compose.test.yml        # Postgres descartável para os testes
└── .gitignore
```

O frontend React do projeto original ainda não foi incorporado nem
auditado — é o próximo passo antes da Etapa 3.

## Como rodar

### Opção 1: Docker (recomendado)

```bash
cp backend/.env.example backend/.env
# edite backend/.env com valores reais — em especial SESSION_SECRET
# (mínimo 32 caracteres; o servidor não sobe com o placeholder)
docker compose up --build
```

O backend sobe em `http://localhost:8000` (`GET /health` responde `{"status":"ok"}`).

> Vindo da Etapa 1? O schema mudou (tabela de sessões, e-mail único) e o
> script de init só roda num volume vazio: recrie com
> `docker compose down -v && docker compose up --build` (apaga os dados de
> desenvolvimento).

### Opção 2: manual

Requer Node.js ≥ 18 e PostgreSQL rodando localmente.

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

Testes de ataque automatizados (jest + supertest) contra um Postgres de
teste separado:

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
