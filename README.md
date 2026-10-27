# Secure Chat — Projeto de Redes

Chat em tempo real com foco em segurança e privacidade, desenvolvido para a
disciplina de Redes (Engenharia de Software). O backend parte de um fork
saneado de [asafebxd/MessageWebApp](https://github.com/asafebxd/MessageWebApp)
(ver atribuição abaixo).

## Status

🚧 Em desenvolvimento. Etapas concluídas:

- [x] **Etapa 0** — Modelo de ameaças ([`docs/00-modelo-ameacas.md`](docs/00-modelo-ameacas.md))
- [x] **Etapa 1** — Saneamento do projeto base ([`docs/01-baseline-seguranca.md`](docs/01-baseline-seguranca.md))
- [ ] Etapa 2 — Autenticação e autorização
- [ ] Etapa 3 — Camada de comunicação (protocolo / socket autenticado)
- [ ] Etapa 4 — Criptografia ponta a ponta (E2EE) + TLS
- [ ] Etapa 5 — Privacidade adicional
- [ ] Etapa 6 — Infraestrutura e validação
- [ ] Etapa 7 — Entrega

> **Importante**: a Etapa 1 corrigiu bugs de configuração e removeu rotas de
> debug perigosas, mas **propositalmente não corrigiu** as falhas de
> autorização e do Socket.IO — essas são o núcleo das Etapas 2 e 3 e ficam
> documentadas em [`docs/01-baseline-seguranca.md`](docs/01-baseline-seguranca.md)
> para servir de comparação "antes/depois" no relatório final.

## Estrutura

```
secure-chat/
├── docs/
│   ├── 00-modelo-ameacas.md       # Etapa 0
│   └── 01-baseline-seguranca.md   # Etapa 1 — registro antes/depois
├── backend/
│   ├── server.js
│   ├── db.js                      # pool único de conexão ao Postgres
│   ├── routes/
│   ├── helpers/
│   ├── database/
│   │   ├── migrations.sql
│   │   └── seeds.sql
│   ├── .env.example
│   ├── Dockerfile
│   └── package.json
├── docker-compose.yml
└── .gitignore
```

O frontend React do projeto original ainda não foi incorporado nem
auditado — é o próximo passo antes da Etapa 3.

## Como rodar

### Opção 1: Docker (recomendado)

```bash
cp backend/.env.example backend/.env
# edite backend/.env com valores reais (senhas, chaves de sessão)
docker compose up --build
```

O backend sobe em `http://localhost:8000`.

### Opção 2: manual

Requer Node.js ≥ 18 e PostgreSQL rodando localmente.

```bash
cd backend
cp .env.example .env
# edite .env
npm install
psql -U seu_usuario -f database/migrations.sql
npm run dev
```

## Atribuição

Backend baseado em [asafebxd/MessageWebApp](https://github.com/asafebxd/MessageWebApp)
(licença ISC), usado como ponto de partida e reescrito ao longo do projeto
conforme o modelo de ameaças e o roteiro de etapas da disciplina.

## Documentação

- [Modelo de ameaças](docs/00-modelo-ameacas.md)
- [Linha de base de segurança (antes/depois)](docs/01-baseline-seguranca.md)
