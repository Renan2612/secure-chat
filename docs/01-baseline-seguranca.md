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
| C | Remetente da mensagem vinha do corpo (`message.user.id`) | `POST /messages` usa sempre `req.session.userId`; campos extras são descartados pelo validador. **Parte HTTP resolvida na Etapa 2; a parte socket, na Etapa 3 (ver abaixo). Na Etapa 3 o `POST /messages` foi removido e este teste renasceu sobre o `MSG_SEND`.** | ~~`backend/tests/messageSender.test.js`~~ → `backend/tests/ws/msgSend.test.js` |
| D | Nenhuma rota verificava se o usuário é membro da sala (IDOR) | Middleware `requireRoomMember` (403) em `GET /messages/:id`, `POST /messages`, `GET /roomUsers/:room`, `POST /updateLastViewed`; `requireAuth` global (401) | `backend/tests/requireRoomMember.test.js`, `backend/tests/requireAuth.test.js` |
| E | `joinRooms` não validava a chave de convite | Chave obrigatória, comparada em tempo constante; chave de 128 bits devolvida só ao criador; criador entra na sala; `listRoomsNotInto` removida e `checkRoomExists` restrita às salas do usuário | `backend/tests/roomInvite.test.js` |
| H | Sessão assinada no cliente (cookie-session), sem revogação | `express-session` + `connect-pg-simple` (tabela `user_sessions`); logout destrói a sessão no servidor; ID regenerado no login | `backend/tests/session.test.js` |

Também na Etapa 2: validação de entrada com zod (`tests/validation.test.js`),
login sem enumeração de usuários e com tempo equalizado (`tests/login.test.js`),
error handler central sem vazamento e remoção de `checkUserExists`
(`tests/hygiene.test.js`), e correção da `migrations.sql`, que criava as
tabelas num banco diferente do usado pelo backend.

## Resolvido na Etapa 3 — protocolo de tempo real

O Socket.IO foi removido e substituído por um protocolo próprio sobre
WebSocket em `/ws`, especificado em
[`03-protocolo.md`](03-protocolo.md). Testes de ataque em
`backend/tests/ws/`, cada um visto falhando antes da correção.

| # | Problema | Correção | Testes que provam |
|---|---|---|---|
| A | Socket sem autenticação | Upgrade só com cookie `sid` de sessão válida no store (401, sem abrir o socket), `Origin` = `CLIENT_URL` (403, contra Cross-Site WebSocket Hijacking), limite de 5 conexões por usuário e 1000 no total; logout fecha as conexões (4401); sessão revalidada a cada 30 s | `tests/ws/upgrade.test.js`, `tests/ws/logout.test.js`, `tests/ws/heartbeat.test.js` |
| B | `broadcast.emit` global | Mapa em memória `sala → conexões`; `SUBSCRIBE` só para membro (`rooms_users`); `MSG_DELIVER` só às conexões inscritas cujo usuário ainda é membro; nada de broadcast | `tests/ws/subscribe.test.js`, `tests/ws/msgSend.test.js` ("B inscrito na sala X NÃO recebe mensagens da sala Y", "quem foi removido da sala deixa de receber, mesmo ainda inscrito") |
| C (socket) | Remetente vindo do cliente | `MSG_SEND` não tem `from` (campos extras descartados); remetente = usuário da sessão da conexão; pertinência rechecada a cada envio, na mesma consulta que grava | `tests/ws/msgSend.test.js` ("campo from forjado é ignorado…", "MSG_SEND de quem foi removido da sala (já inscrito) é rejeitado") |

Também na Etapa 3: um único caminho de envio (`POST /messages` removido;
histórico `GET /messages/:id` paginado, `tests/messagesHistory.test.js`),
idempotência por `cid` (`tests/ws/idempotency.test.js`), validação do
envelope e do body opaco (`tests/ws/msgValidation.test.js`,
`tests/ws/frames.test.js`), rate limit com quarentena
(`tests/ws/rateLimit.test.js`), backpressure
(`tests/ws/backpressure.test.js`), nenhum body em log
(`tests/ws/logging.test.js`) e o cliente de referência
`backend/tools/ws-client.js` (`tests/tools/wsClient.test.js`).

## Resolvido na Etapa 4a — TLS, proxy reverso e origem única

Detalhes em [`04-tls-e-proxy.md`](04-tls-e-proxy.md). Os controles de rede
são provados por `scripts/verify-tls.sh` contra a stack no ar (33 provas;
sai com código != 0 se alguma falhar); os do backend, por testes
automatizados.

| # | Problema | Correção | Evidência |
|---|---|---|---|
| G | Sem TLS: tráfego HTTP/WS em texto claro | Caddy como proxy reverso e terminador de TLS (TLS 1.2/1.3, só ECDHE + AEAD, HSTS de 1 ano); HTTP → 308 para HTTPS; origem única `https://localhost` (`/api/*`, `/ws`); backend e banco sem portas no host; cookie `sid` com `Secure`; `trust proxy` = 1 salto exato; ws-client só por `wss://` com verificação de certificado | `scripts/verify-tls.sh`; `backend/tests/proxy.test.js`, `backend/tests/ws/upgradeIp.test.js`, `backend/tests/tools/wsClientTls.test.js`; captura no Wireshark ([`04-tls-e-proxy.md`](04-tls-e-proxy.md) §10) |

**Atenção:** o TLS termina no proxy. Na Etapa 4a, proxy, backend e banco
ainda viam o conteúdo em claro; isso é o item F, resolvido na Etapa 4b-1.

## Resolvido na Etapa 4b-1 — criptografia ponta a ponta (núcleo)

Detalhes em [`05-e2ee.md`](05-e2ee.md). Provado por `scripts/verify-e2ee.sh`
contra a stack no ar (21 provas, com controles positivos; validado com
duas mutações que fazem o script falhar) e por testes de ataque.

| # | Problema | Correção | Evidência |
|---|---|---|---|
| F | Mensagens em texto claro no Postgres (e no proxy/backend, onde o TLS termina) | Cada mensagem é cifrada (AES-256-GCM) e assinada (ECDSA P-256) no cliente com a chave da sala, que só existe embrulhada para cada membro (ECDH + HKDF); o servidor aceita só envelope E2EE v1 bem formado (`E2EE_REQUIRED`, `KEY_VERSION_MISMATCH`) e o banco tem `CHECK` de formato; chaves privadas num keystore cifrado no cliente; TOFU + número de segurança | `scripts/verify-e2ee.sh` (o marcador não aparece no banco nem na captura da rede interna, nem decodificado de base64; cada cliente decifra o do outro; o banco só tem o envelope); `backend/tests/ws/e2eeMessages.test.js`, `backend/tests/roomKeys.test.js`, `backend/tests/keys.test.js`, `backend/tests/e2ee/*.test.js`, `backend/tests/tools/wsClientE2ee.test.js` |

**Continua visível ao servidor:** metadados (quem, quando, tamanho em blocos
de 128 bytes) e quem é membro de cada sala; ver [`05-e2ee.md`](05-e2ee.md) §10.

## Pendente — propositalmente NÃO corrigido ainda

Estes problemas são o núcleo das próximas etapas e foram deixados como estão
para servir de comparação "antes/depois" no relatório final. Os itens
marcados ✅ foram resolvidos nas Etapas 2 e 3 (ver seções anteriores); as
linhas foram mantidas para preservar o registro. Os itens das Etapas 2, 3
e 4a estão nas seções anteriores.

| # | Problema | Onde | Etapa que resolve |
|---|---|---|---|
| A | Socket.IO sem autenticação: qualquer um conecta sem sessão válida | `server.js` | ✅ **Resolvido na Etapa 3** |
| B | Socket.IO usa `broadcast.emit` global — todo cliente conectado recebe mensagens de **todas** as salas, não só da sua | `server.js` | ✅ **Resolvido na Etapa 3** |
| C | Servidor não define o remetente da mensagem — vem do corpo enviado pelo cliente (`message.user.id`), permitindo forjar identidade | ~~`routes/messages.js`~~, ~~socket~~ | ✅ HTTP: Etapa 2 · ✅ socket: Etapa 3 |
| D | Nenhuma rota verifica se o usuário autenticado é membro da sala antes de ler/escrever (IDOR) | `routes/messages.js`, `routes/rooms.js` | ✅ **Resolvido na Etapa 2** |
| E | `joinRooms` não valida a chave de convite da sala — qualquer usuário autenticado entra em qualquer sala só sabendo o `idRoom` | `routes/rooms.js` | ✅ **Resolvido na Etapa 2** |
| F | Mensagens armazenadas em texto claro no Postgres — o admin do banco lê tudo | `database/migrations.sql` | ✅ **Resolvido na Etapa 4b-1** |
| G | Sem TLS — tráfego HTTP/WS em texto claro | infraestrutura | ✅ **Resolvido na Etapa 4a** |
| H | Sessão assinada no cliente (cookie-session) sem possibilidade de revogação centralizada | `server.js` | ✅ **Resolvido na Etapa 2** |
| I | Frontend React ainda não auditado | `frontend/` | Ainda pendente (fora do escopo das Etapas 3 e 4a) |

## Vulnerabilidades de dependências (`npm audit`)

Ao rodar `npm install`, o `bcrypt` original (5.1.x) trazia uma cadeia de
build nativo (`node-pre-gyp` → `tar`) com vulnerabilidade **crítica**
(path traversal). Corrigido atualizando para `bcrypt@^6`.

Na Etapa 1 restava 1 vulnerabilidade **alta**, em `braces` (via `chokidar`
→ `nodemon`), dependência só de desenvolvimento. Ela **não aparece mais**
na auditoria de 28/10/2026 (as dependências foram atualizadas desde então).

**Risco aceito (28/10/2026): 5 vulnerabilidades baixas em `deepmerge`**
(GHSA-gcqx-w48m-w2h4, poluição de protótipo em `mergeObject()`), todas pela
cadeia do **jest** (`jest` → `@jest/core`/`jest-cli` → `jest-config` →
`deepmerge`). Motivos para aceitar:

- é dependência **só de desenvolvimento/teste**: `npm audit --omit=dev`
  responde **0 vulnerabilidades**, e a imagem Docker instala com
  `npm ci --omit=dev`;
- o `deepmerge` só mescla a configuração do próprio jest, sem entrada de
  usuário;
- a única "correção" oferecida (`npm audit fix --force`) **rebaixa o jest
  para a versão 25**, uma quebra maior e uma troca pior.

Reavaliar quando o jest publicar versão com o `deepmerge` corrigido.

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
docker compose --env-file backend/.env up --build
scripts/verify-tls.sh   # Etapa 4a: provas de TLS e da origem única
scripts/verify-e2ee.sh  # Etapa 4b-1: provas da criptografia ponta a ponta
```
