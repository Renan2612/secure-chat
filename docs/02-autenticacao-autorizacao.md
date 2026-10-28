# Etapa 2 — Autenticação e autorização (backend)

> Resolve os itens **C**, **D**, **E** e **H** do
> [`01-baseline-seguranca.md`](01-baseline-seguranca.md), além de validação
> de entrada, endurecimento do login e higiene de erros/logs.
> O Socket.IO (itens A e B) **não** foi alterado: é a Etapa 3.
>
> **Atualização (Etapa 3):** o Socket.IO foi substituído por um protocolo
> próprio em `/ws` e o **`POST /messages` foi removido**: o envio é só
> pelo `MSG_SEND` e `GET /messages/:id` passou a ser paginado. As
> menções ao `POST /messages` abaixo descrevem a Etapa 2; o contrato
> atual está em [`03-protocolo.md`](03-protocolo.md) §10.

Cada correção tem um **teste de ataque** automatizado em `backend/tests/`,
escrito antes da correção (TDD) e visto falhando contra o código antigo.

## 1. Como rodar os testes

```bash
docker compose -f docker-compose.test.yml up -d --wait   # Postgres de teste (porta 5433, tmpfs)
cd backend
npm test                                                 # jest --runInBand, ~1 min
```

O banco de teste é separado do de desenvolvimento e é recriado a partir da
própria `database/migrations.sql` no início da suíte (`tests/globalSetup.js`).

## 2. Decisões de projeto

### 2.1 Sessão no servidor (item H)

| Antes | Depois |
|---|---|
| `cookie-session`: dados da sessão assinados **dentro** do cookie | `express-session` + `connect-pg-simple`: cookie carrega só um ID aleatório assinado; os dados ficam na tabela `user_sessions` |
| Logout só pedia ao navegador para esquecer o cookie; uma cópia continuava válida até expirar | Logout apaga a linha no banco: o cookie copiado deixa de funcionar na hora |
| Sem regeneração de ID | `req.session.regenerate()` no login (contra *session fixation*) |

Cookie: nome genérico `sid`, `httpOnly`, `sameSite: "lax"`, `secure` quando
`NODE_ENV=production`, `maxAge` de **8 horas** (uma jornada de uso; antes
eram 24 h). `saveUninitialized: false`: visitante anônimo não ganha sessão
nem cookie.

Segredo: `SESSION_SECRET` é **obrigatório** e precisa de ao menos 32
caracteres; o servidor se recusa a subir sem ele (o placeholder do
`.env.example` é propositalmente curto, para não subir com um segredo
público). `SESSION_SECRET_PREVIOUS` (opcional) permite rotação sem derrubar
sessões ativas.

Proxy reverso: `TRUST_PROXY` (opcional, número de proxies na frente do app).
Sem ele, atrás de um proxy HTTPS o Express acharia que a conexão é HTTP e
não emitiria o cookie `Secure`, e o rate limit veria o IP do proxy. Não deve
ser definido sem proxy, porque permitiria ao cliente forjar `X-Forwarded-For`.

### 2.2 Autenticação: `requireAuth` global

Em vez de aplicar o middleware rota a rota, ele é registrado com
`app.use(requireAuth)` **logo depois das rotas públicas** (`/health`,
`/register`, `/login`). Consequências:

- toda rota nova nasce protegida — esquecer o middleware não abre buraco;
- até rota inexistente responde **401** a quem não tem sessão (atacante sem
  conta não consegue mapear a API); com sessão, responde 404.

### 2.3 Autorização por sala: `requireRoomMember` (item D)

Consulta `rooms_users` para `(sala, req.session.userId)`. A sala vem de
`:id`, `:room` ou `room` no corpo. **Sala inexistente e sala alheia recebem
a mesma resposta 403**, para não revelar quais IDs de sala existem. Como a
FK garante que todo vínculo aponta para uma sala real, "é membro" já implica
"a sala existe" (requisito do item 4).

### 2.4 Remetente definido pelo servidor (item C)

`POST /messages` grava sempre `req.session.userId`. O validador (zod)
descarta campos não previstos, então `user`, `user_id` etc. enviados pelo
cliente nem chegam ao handler. O item C também envolve o Socket.IO, que
continua aceitando o remetente do cliente — **isso fica para a Etapa 3**.

### 2.5 Convite de sala (item E)

- `createRoom` gera uma chave de **128 bits** (`crypto.randomBytes(16)`; antes
  eram 64 bits) e a devolve **somente** nessa resposta, ao criador. O criador
  é inscrito na sala na mesma transação.
- `joinRooms` exige `{ idRoom, key }`. A comparação usa
  `crypto.timingSafeEqual` sobre o **SHA-256** das duas chaves: os digests
  têm sempre 32 bytes, o que resolve o requisito de tamanhos iguais do
  `timingSafeEqual` sem lançar exceção nem vazar o tamanho da chave real.
- Chave errada e sala inexistente → mesmo `403 { message: "Convite inválido" }`.
- `UNIQUE (room, user_id)` em `rooms_users`; entrar de novo é idempotente.

**Reavaliação de `listRoomsNotInto` e `checkRoomExists`** (pedido no item 5):

| Rota | Problema | Decisão (ajuste mínimo) |
|---|---|---|
| `GET /listRoomsNotInto` | Listava nome e ID de **todas** as salas das quais o usuário não é membro — ou seja, as salas privadas de todo mundo. Com convite obrigatório, a lista não serve para entrar e só vaza metadados (nomes de sala podem ser sensíveis). | **Removida** (404). Quem convida passa ao convidado o ID da sala e a chave, por fora do sistema. |
| `POST /checkRoomExists` | Buscava o nome em todas as salas e devolvia ID + nome de salas alheias. | **Mantida**, mas busca só entre as salas das quais o usuário é membro (uso legítimo: avisar "você já tem uma sala com esse nome"). |

### 2.6 Validação de entrada (zod)

Schemas em `backend/validation/schemas.js`, aplicados pelo middleware
`backend/middleware/validate.js`, que substitui `req.body`/`req.params` pela
versão validada (tipos convertidos, campos extras descartados).

| Campo | Regra |
|---|---|
| e-mail | `trim` + minúsculas, formato de e-mail, até 254 caracteres |
| senha (cadastro) | 10+ caracteres e **no máximo 72 bytes UTF-8** (o bcrypt ignora o que passa de 72 bytes; limite em bytes, não em caracteres) |
| senha (login) | 1 a 72 bytes (a regra de tamanho mínimo é só do cadastro, para não mudar a resposta conforme a senha tentada) |
| nome do usuário / da sala | `trim`, 1 a 100 caracteres |
| IDs | inteiros positivos até 2147483647 (limite do `INTEGER` do Postgres); no corpo precisam ser número JSON, na URL só dígitos |
| mensagem | `trim`, 1 a 500 caracteres (tamanho da coluna) |
| chave de convite | texto de 1 a 128 caracteres |
| `idLastMessage` | inteiro ≥ 0 |

Qualquer falha → `400 { message: "Requisição inválida" }`, sem ecoar a
entrada nem dizer qual regra falhou.

### 2.7 Login sem enumeração de usuários

- "E-mail não existe" e "senha errada" → mesmo `401 { message: "Credenciais inválidas" }`
  (antes: `404 "Usuário não encontrado"` × `401 "Senha incorreta"`).
- Quando o e-mail não existe, o servidor roda `bcrypt.compare` contra um
  **hash fictício de mesmo custo (12)**, para o tempo de resposta não
  denunciar a inexistência (medido no teste: sem isso, ~2 ms × ~170 ms).
- `users.email` passa a ser `UNIQUE` e com `CHECK (email = LOWER(email))`;
  a API normaliza antes de gravar.
- Rate limit: além do limite por IP já existente (20 / 15 min em `/login` e
  `/register`), o login tem limite **por conta** (e-mail normalizado):
  10 tentativas **falhas** / 15 min, contra força bruta distribuída por
  muitos IPs. Só respostas **401** contam: logins corretos não gastam a
  cota, e erros do servidor (ex.: banco fora) não travam a conta do dono.

### 2.8 Higiene de erros e logs

- Error handler central (`backend/middleware/errorHandler.js`): 500 sempre
  `{ message: "Erro interno" }`, sem stack, mensagem do Postgres nem nome de
  tabela. Erros do cliente sinalizados pelo Express/body-parser (JSON
  malformado, charset não suportado, parâmetro de URL malformado…) mantêm
  seu status 4xx com `Requisição inválida` (413 para corpo acima de 10 kb) e
  não poluem o log de erros internos.
- O log de erro interno registra data/hora, método, rota, código do erro,
  metadados de schema do pg (constraint, tabela, coluna) e o **stack**
  (arquivo/linha). **Não** registra corpo da requisição (senhas), cabeçalhos
  (cookie) nem `err.detail` do pg (que costuma conter valores das colunas,
  ex.: o e-mail num erro de duplicidade). Os `console.log("err", err)`
  espalhados pelas rotas, que despejavam o objeto inteiro, foram removidos.
  Ressalva: algumas mensagens do pg citam a entrada (ex.: erro 22P02); a
  validação impede isso hoje, mas uma lacuna futura num schema poderia levar
  entrada do usuário ao log.
- `createRoom` registra um listener de `'error'` no client retirado do pool:
  sem ele, uma queda de conexão no meio da transação **derrubava o processo
  inteiro** (reproduzido em teste). Falha no `ROLLBACK` é registrada e a
  conexão é descartada.
- Se a gravação da sessão falha no login, a sessão é descartada antes do
  500 — antes, o cliente via erro mas recebia um cookie autenticado.
- `GET /health` consulta o banco (`SELECT 1`) e responde `503` se ele
  estiver fora, para o orquestrador não mandar tráfego a uma instância inútil.
- `POST /checkUserExists` **removida**: respondia a qualquer um se um e-mail
  tinha conta. O cadastro já informa e-mail duplicado (409), então ela não
  era essencial. (O frontend ainda não está no repositório; se ele usar essa
  rota, deve passar a tratar o 409 do `/register`.)

### 2.9 Correção encontrada pelo caminho: migração no banco errado

A `migrations.sql` original começava com `CREATE DATABASE messagewebapp;
\c messagewebapp;`. No Docker, o Postgres cria `secure_chat` (`POSTGRES_DB`)
e roda o script de init conectado a ele; o script então criava **outro**
banco e as tabelas iam para lá, enquanto o backend (`DB_NAME=secure_chat`)
não encontrava nenhuma tabela. As duas linhas foram removidas: o script
agora roda no banco já selecionado.

## 3. Fluxo de login e sessão

```
Cliente                                Servidor                         Postgres
  │ POST /login {email, password}        │                                  │
  │─────────────────────────────────────▶│ rate limit (IP) → validate (zod) │
  │                                      │ → rate limit (conta)             │
  │                                      │ SELECT id,name,password ────────▶│
  │                                      │ bcrypt.compare(senha, hash       │
  │                                      │   ou HASH_FICTICIO)              │
  │                                      │ falhou → 401 Credenciais inválidas
  │                                      │ ok → session.regenerate()        │
  │                                      │      session.userId = id         │
  │                                      │      INSERT user_sessions ──────▶│
  │◀─────── 200 {id,name} + Set-Cookie: sid=s:<id>.<hmac>; HttpOnly; SameSite=Lax
  │                                      │                                  │
  │ GET /messages/7  (Cookie: sid=…)     │                                  │
  │─────────────────────────────────────▶│ carrega sessão pelo ID ─────────▶│
  │                                      │ requireAuth (tem userId?) → 401  │
  │                                      │ validate (:id inteiro?) → 400    │
  │                                      │ requireRoomMember ──────────────▶│ rooms_users
  │                                      │   não é membro → 403             │
  │◀──────────────── 200 [mensagens] ────│                                  │
  │                                      │                                  │
  │ POST /logout (Cookie: sid=…)         │                                  │
  │─────────────────────────────────────▶│ session.destroy() ──────────────▶│ DELETE
  │◀──── 204 + Set-Cookie: sid=; Expires=1970 ─│                            │
```

## 4. Tabela de rotas

| Rota | Quem pode acessar | Verificações aplicadas (em ordem) | Teste de ataque |
|---|---|---|---|
| `GET /health` | qualquer um | — (consulta o banco) | `requireAuth.test.js`, `hygiene.test.js` |
| `POST /register` | qualquer um | rate limit IP · zod | `validation.test.js`, `login.test.js` |
| `POST /login` | qualquer um | rate limit IP · zod · rate limit por conta (falhas) | `login.test.js` |
| `POST /logout` | autenticado | sessão | `session.test.js` |
| `GET /rooms` | autenticado (vê só as próprias salas) | sessão · filtro por `userId` na consulta | `requireAuth.test.js` |
| `POST /createRoom` | autenticado | sessão · zod | `roomInvite.test.js` |
| `POST /joinRooms` | autenticado **com a chave de convite** | sessão · zod · chave (tempo constante) | `roomInvite.test.js` |
| `POST /checkRoomExists` | autenticado (busca só nas próprias salas) | sessão · zod · filtro por `userId` | `roomInvite.test.js` |
| `GET /messages/:id` | **membro da sala** | sessão · zod · `requireRoomMember` | `requireRoomMember.test.js` |
| `POST /messages` | **membro da sala** (remetente = sessão) | sessão · zod · `requireRoomMember` | `requireRoomMember.test.js`, `messageSender.test.js` |
| `GET /roomUsers/:room` | **membro da sala** | sessão · zod · `requireRoomMember` | `requireRoomMember.test.js` |
| `POST /updateLastViewed` | **membro da sala** (só o próprio marcador) | sessão · zod · `requireRoomMember` | `requireRoomMember.test.js` |
| `POST /checkUserExists` | — | **removida** | `hygiene.test.js` |
| `GET /listRoomsNotInto` | — | **removida** | `roomInvite.test.js`, `hygiene.test.js` |
| `/session`, `/sessionRoom` | — | removidas na Etapa 1; testadas aqui | `hygiene.test.js` |
| qualquer outra | — | sem sessão: 401; com sessão: 404 | `requireAuth.test.js`, `hygiene.test.js` |

## 5. Mudanças de contrato da API (para o frontend)

Todas as respostas de erro agora seguem o formato **`{ "message": string }`**,
com textos genéricos:

| Status | `message` | Quando |
|---|---|---|
| 400 | `Requisição inválida` | entrada fora do formato (inclui JSON malformado) |
| 401 | `Não autenticado` | sem sessão, sessão expirada ou destruída |
| 401 | `Credenciais inválidas` | login com e-mail inexistente **ou** senha errada |
| 403 | `Acesso negado` | não é membro da sala |
| 403 | `Convite inválido` | chave de convite errada ou sala inexistente |
| 404 | `Não encontrado` | rota inexistente (com sessão) |
| 409 | `E-mail já cadastrado` | cadastro com e-mail existente |
| 413 | `Requisição muito grande` | corpo acima de 10 kb |
| 415 | `Requisição inválida` | charset/encoding do corpo não suportado |
| 429 | `Muitas tentativas. Tente novamente em instantes.` | rate limit |
| 500 | `Erro interno` | qualquer falha inesperada |

Mudanças por rota:

| Rota | Antes | Agora |
|---|---|---|
| todas (exceto públicas) | funcionavam sem sessão | exigem o cookie `sid`; o frontend deve enviar `credentials: "include"` e tratar **401** redirecionando para o login |
| `POST /login` | `201 { message: "saves" }`; `404` usuário inexistente | `200 { id, name }`; `401 Credenciais inválidas` para qualquer falha. E-mail é normalizado (maiúsculas/espaços não importam) |
| `POST /register` | senha sem regra | senha com **10+ caracteres** e até 72 bytes; nome até 100 |
| `POST /logout` | `200` | `204` (sem corpo); o cookie é apagado pelo servidor |
| `POST /messages` | corpo `{ room: { id }, user: { id }, message }`; resposta: array | corpo **`{ room: <id>, message }`** (`user` é ignorado); resposta: **objeto** `{ id, room, user_id, message, dt_message }`, status 201 |
| `POST /createRoom` | `200 [{ id, name }]` | **`201 { id, name, key }`** — o criador já é membro; a `key` só aparece aqui e o frontend deve exibi-la ao criador para ele repassar |
| `POST /joinRooms` | corpo `{ idRoom }`; resposta: linha de `rooms_users` | corpo **`{ idRoom, key }`**; resposta `200 { id, name }`; `403 Convite inválido` |
| `POST /checkRoomExists` | buscava em todas as salas | busca só nas salas do próprio usuário |
| `POST /updateLastViewed` | aceitava qualquer sala | corpo `{ room: <id>, idLastMessage: <inteiro ≥ 0> }`, só para salas das quais é membro |
| `GET /listRoomsNotInto` | lista de salas alheias | **removida** (404) — a tela de "entrar em sala" passa a pedir ID + chave |
| `POST /checkUserExists` | `{ exists }` | **removida** (404) — usar o 409 do `/register` |
| `GET /health` | — | nova: `200 { status: "ok" }`, ou `503 { status: "indisponível" }` se o banco estiver fora |

## 6. Limitações conhecidas

1. **Socket.IO continua aberto** (itens A e B, e a parte socket do item C):
   conexão sem autenticação, broadcast global, remetente vindo do cliente.
   Mesmo com a API HTTP fechada, quem conecta no socket recebe as mensagens
   em tempo real de todas as salas. **Prioridade da Etapa 3.**
2. **Cadastro ainda permite enumeração**: o `409 E-mail já cadastrado`
   revela que a conta existe (achado também apontado pelo security-guidance).
   Resolver de verdade exige confirmação por e-mail (sempre responder
   "verifique seu e-mail"), fora do escopo. Mitigado pelo rate limit por IP.
3. **Travamento proposital de conta**: o limite por conta no login pode ser
   usado para bloquear o login de alguém por 15 min, errando a senha de
   propósito. Compromisso aceito em troca da proteção contra força bruta
   distribuída; alternativas (CAPTCHA, atraso progressivo) ficam para depois.
4. **Rate limit em memória**: os contadores ficam no processo. Com mais de
   uma instância do backend, cada uma conta separado (exigiria um store
   compartilhado, ex.: Redis ou Postgres).
5. **Chave de convite em texto claro no banco** e **sem revogação/rotação**:
   quem tem a chave entra para sempre, e quem lê a tabela `rooms` (admin)
   vê todas as chaves. Para o admin isso é coerente com o modelo de ameaças
   (o conteúdo será protegido pela E2EE da Etapa 4), mas guardar só o hash
   da chave e permitir regenerá-la são melhorias simples para depois.
6. **Sem remoção de membros / saída de sala** e **sem expiração de sessões
   por inatividade** (só o `maxAge` absoluto de 8 h).
7. **CSRF**: a proteção vem de `sameSite: "lax"` + CORS restrito à origem do
   frontend + corpo obrigatoriamente JSON (formulários de outros sites não
   conseguem enviar `application/json` sem preflight). Não há token CSRF;
   reavaliar se algum dia houver rota que aceite formulário ou GET com efeito.
8. **Mensagens limitadas a 500 caracteres** (tamanho atual da coluna). Na
   Etapa 4 o conteúdo vira texto cifrado, que é maior: a coluna e o limite
   do zod precisarão crescer juntos.
9. `database/seeds.sql` grava senhas em texto puro (`'12345'`), que não são
   hashes bcrypt válidos: esses usuários de exemplo não conseguem logar.
   Não é usado pelo Docker nem pelos testes; corrigir ou remover depois.
10. **Migração destrutiva**: `migrations.sql` é um script de schema completo
    (com `DROP TABLE`), não incremental. Quem já tem o volume do Docker da
    Etapa 1 precisa recriá-lo: `docker compose down -v && docker compose up --build`
    (apaga os dados de desenvolvimento).
