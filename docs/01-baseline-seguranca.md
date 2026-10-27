# Etapa 1 — Linha de base de segurança (antes / depois)

Registro de tudo que foi encontrado na auditoria do projeto original
([asafebxd/MessageWebApp](https://github.com/asafebxd/MessageWebApp)) e o
que foi corrigido já na Etapa 1 (saneamento) versus o que fica pendente para
etapas seguintes. Este documento serve de evidência para o relatório final
("antes e depois").

## Corrigido na Etapa 1 (saneamento)

| # | Problema no original | Onde | Correção aplicada |
|---|---|---|---|
| 1 | Rota `POST /session` aceitava `userId` do corpo da requisição e gravava direto na sessão — qualquer um podia se passar por qualquer usuário sem senha | `server.js` | Rota removida |
| 2 | Rotas de debug `/sessionRoom` e `GET /session` expunham dados de sessão sem necessidade | `server.js` | Rotas removidas |
| 3 | `checkUserExists` devolvia a linha inteira do usuário, **incluindo o hash bcrypt da senha** | `routes/login.js` | Agora devolve só `{ exists: boolean }` |
| 4 | Chave de convite de sala fixa (`"41421"`) para todas as salas | `routes/rooms.js` | Gerada aleatoriamente por sala com `crypto.randomBytes` (a *validação* da chave ainda não existe — ver pendências) |
| 5 | `GET /logout` — logout por GET pode ser disparado por uma tag `<img>` em outro site (CSRF) | `server.js` | Mudado para `POST /logout` |
| 6 | Duas chaves de assinatura do cookie eram a mesma variável repetida (`[key1, key1]`), impedindo rotação real | `server.js` | Duas variáveis distintas: `SESSION_KEY_1` / `SESSION_KEY_2` |
| 7 | Cookie de sessão sem `httpOnly`, `secure` nem `sameSite` explícitos | `server.js` | Adicionados os três, com `secure` condicionado a `NODE_ENV=production` |
| 8 | `cors` do Socket.IO usava `method` (singular) — não tinha efeito nenhum, CORS ficava sem restrição real | `server.js` | Corrigido para `methods` |
| 9 | `dotenv.config()` chamado depois dos `require` das rotas — risco de variáveis `undefined` na inicialização | `server.js` | Movido para a primeira linha do arquivo |
| 10 | `process.env.DB_NAME` usado como **usuário** do banco (bug de nomenclatura) | todas as rotas | Centralizado em `db.js`, variáveis renomeadas corretamente (`DB_USER`, `DB_HOST`, `DB_NAME`, ...) |
| 11 | Cada rota criava um `new Pool()` e chamava `pool.end()` a cada requisição | todas as rotas | Pool único compartilhado (`db.js`) |
| 12 | Sem `helmet`, sem rate limiting em `/login` e `/register` | `server.js` | Adicionados `helmet()` e rate limit (20 tentativas / 15 min) |
| 13 | Sem limite de tamanho do corpo da requisição | `server.js` | `express.json({ limit: "10kb" })` |
| 14 | Dependências `pool` e `psql` no `package.json` (não utilizadas, parecem instalação por engano) | `package.json` | Removidas |
| 15 | Dois mecanismos de sessão concorrentes (`cookie-session` e `express-session`, um comentado) | `server.js` | Mantido só `cookie-session`; decisão final de arquitetura de sessão fica para a Etapa 2 |
| 16 | `res.status(200);` sem `.send()`/`.json()` em `registerUser` — requisição ficava pendurada no cliente | `routes/register.js` | Corrigido para responder sempre |
| 17 | `loginUser`: quando a senha estava errada, nenhuma resposta era enviada (`else` vazio) | `routes/login.js` | Agora responde `401` |
| 18 | Node 16 e dependências desatualizadas (2022) | `package.json` | Atualizado para Node ≥ 18 e versões atuais das libs |
| 19 | Sem `.env.example`, sem Docker Compose, README mínimo | raiz do projeto | Adicionados `.env.example`, `docker-compose.yml`, `Dockerfile`, este README |

## Resolvido na Etapa 2 — autenticação e autorização

Detalhes, decisões e mudanças de contrato em
[`02-autenticacao-autorizacao.md`](02-autenticacao-autorizacao.md). Cada item
tem testes de ataque automatizados (`cd backend && npm test`), vistos
falhando contra o código antigo antes da correção.

| # | Problema | Correção | Testes que provam |
|---|---|---|---|
| C | Remetente da mensagem vinha do corpo (`message.user.id`) | `POST /messages` usa sempre `req.session.userId`; campos extras são descartados pelo validador. **Parte HTTP resolvida; o socket continua aceitando o remetente do cliente (Etapa 3, item A/B).** | `backend/tests/messageSender.test.js` |
| D | Nenhuma rota verificava se o usuário é membro da sala (IDOR) | Middleware `requireRoomMember` (403) em `GET /messages/:id`, `POST /messages`, `GET /roomUsers/:room`, `POST /updateLastViewed`; `requireAuth` global (401) | `backend/tests/requireRoomMember.test.js`, `backend/tests/requireAuth.test.js` |
| E | `joinRooms` não validava a chave de convite | Chave obrigatória, comparada em tempo constante; chave de 128 bits devolvida só ao criador; criador entra na sala; `listRoomsNotInto` removida e `checkRoomExists` restrita às salas do usuário | `backend/tests/roomInvite.test.js` |
| H | Sessão assinada no cliente (cookie-session), sem revogação | `express-session` + `connect-pg-simple` (tabela `user_sessions`); logout destrói a sessão no servidor; ID regenerado no login | `backend/tests/session.test.js` |

Também na Etapa 2: validação de entrada com zod (`tests/validation.test.js`),
login sem enumeração de usuários e com tempo equalizado (`tests/login.test.js`),
error handler central sem vazamento e remoção de `checkUserExists`
(`tests/hygiene.test.js`), e correção da `migrations.sql`, que criava as
tabelas num banco diferente do usado pelo backend.

## Pendente — propositalmente NÃO corrigido ainda

Estes problemas são o núcleo das próximas etapas e foram deixados como estão
para servir de comparação "antes/depois" no relatório final. Os itens
marcados ✅ foram resolvidos na Etapa 2 (ver seção anterior); as linhas
foram mantidas para preservar o registro.

| # | Problema | Onde | Etapa que resolve |
|---|---|---|---|
| A | Socket.IO sem autenticação: qualquer um conecta sem sessão válida | `server.js` | Etapa 3 |
| B | Socket.IO usa `broadcast.emit` global — todo cliente conectado recebe mensagens de **todas** as salas, não só da sua | `server.js` | Etapa 3 |
| C | Servidor não define o remetente da mensagem — vem do corpo enviado pelo cliente (`message.user.id`), permitindo forjar identidade | ~~`routes/messages.js`~~ (✅ Etapa 2), socket | ✅ HTTP: Etapa 2 · ⏳ socket: Etapa 3 |
| D | Nenhuma rota verifica se o usuário autenticado é membro da sala antes de ler/escrever (IDOR) | `routes/messages.js`, `routes/rooms.js` | ✅ **Resolvido na Etapa 2** |
| E | `joinRooms` não valida a chave de convite da sala — qualquer usuário autenticado entra em qualquer sala só sabendo o `idRoom` | `routes/rooms.js` | ✅ **Resolvido na Etapa 2** |
| F | Mensagens armazenadas em texto claro no Postgres — o admin do banco lê tudo | `database/migrations.sql` | Etapa 4 (E2EE) |
| G | Sem TLS — tráfego HTTP/WS em texto claro | infraestrutura | Etapa 4 |
| H | Sessão assinada no cliente (cookie-session) sem possibilidade de revogação centralizada | `server.js` | ✅ **Resolvido na Etapa 2** |
| I | Frontend React ainda não auditado | `frontend/` | Próxima tarefa, antes da Etapa 3 |

## Vulnerabilidades de dependências (`npm audit`)

Ao rodar `npm install`, o `bcrypt` original (5.1.x) trazia uma cadeia de
build nativo (`node-pre-gyp` → `tar`) com vulnerabilidade **crítica**
(path traversal). Corrigido atualizando para `bcrypt@^6`.

Resta 1 vulnerabilidade **alta**, em `braces` (via `chokidar` → `nodemon`).
É uma dependência **somente de desenvolvimento** (hot-reload local), não vai
para produção, e não há correção upstream disponível sem downgrade do
`nodemon` para uma versão muito mais antiga (pior troca). Risco aceito e
documentado — reavaliar quando o nodemon publicar correção.

## Como verificar

```bash
cd backend
cp .env.example .env   # preencher com valores reais
npm install
npm run dev
```

Ou com Docker:

```bash
cp backend/.env.example backend/.env
docker compose up --build
```
