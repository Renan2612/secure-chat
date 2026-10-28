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
- [ ] Etapa 4 — Criptografia ponta a ponta (E2EE) + TLS
- [ ] Etapa 5 — Privacidade adicional
- [ ] Etapa 6 — Infraestrutura e validação
- [ ] Etapa 7 — Entrega

> **Importante**: a Etapa 3 trocou o Socket.IO por um protocolo próprio
> sobre WebSocket em `/ws`, autenticado pela mesma sessão da API e com
> entrega só aos membros de cada sala. **Ainda não há TLS nem criptografia
> ponta a ponta**: senha, cookie e mensagens trafegam e ficam no banco em
> claro (Etapa 4). O `POST /messages` foi removido; o envio é só pelo
> WebSocket (contrato para o frontend em
> [`docs/03-protocolo.md`](docs/03-protocolo.md) §10).

## Estrutura

```
secure-chat/
├── docs/
│   ├── 00-modelo-ameacas.md          # Etapa 0
│   ├── 01-baseline-seguranca.md      # Etapa 1 — registro antes/depois
│   ├── 02-autenticacao-autorizacao.md # Etapa 2
│   └── 03-protocolo.md           # Etapa 3 — especificação do protocolo
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
├── docker-compose.yml
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
(sem ele, o compose recusa subir: `DB_PASSWORD` é obrigatório). Banco e
backend ficam publicados só em `127.0.0.1`, e o backend roda na imagem como
usuário sem privilégios (`node`).

O backend sobe em `http://localhost:8000` (`GET /health` responde `{"status":"ok"}`);
o canal em tempo real fica em `ws://localhost:8000/ws`.

Para testar o chat pelo terminal (a partir de `backend/`, com usuário e
sala já criados):

```bash
CHAT_PASSWORD='sua-senha' node tools/ws-client.js --email voce@example.com --room 1
```

> Vindo de uma etapa anterior? O schema mudou (Etapa 2: tabela de sessões,
> e-mail único; Etapa 3: `messages.message` em TEXT e coluna `cid`) e o
> script de init só roda num volume vazio: recrie com
> `docker compose down -v && docker compose --env-file backend/.env up --build`
> (apaga os dados de desenvolvimento). Se o volume foi criado sem o
> `--env-file`, a senha do banco é a antiga padrão (`troque_esta_senha`) e o
> `/health` responde 503: recrie o volume ou ajuste a senha com
> `ALTER USER` no `psql` do container.

### Opção 2: manual

Requer Node.js ≥ 22 e PostgreSQL rodando localmente.

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
