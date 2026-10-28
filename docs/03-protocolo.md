# Etapa 3 — Protocolo de tempo real (secure-chat/1)

> Especificação no estilo de uma mini-RFC. As palavras **DEVE**, **NÃO
> DEVE**, **DEVERIA** e **PODE** têm o sentido da RFC 2119.
> Resolve os itens **A**, **B** e a parte socket do **C** de
> [`01-baseline-seguranca.md`](01-baseline-seguranca.md).
> Implementação: `backend/realtime/` (`protocol.js` define tipos, limites e
> códigos; `index.js` faz o upgrade; `connection.js` é a máquina de estados
> de cada conexão; `handlers.js` trata os pacotes; `registry.js` guarda as
> conexões e inscrições em memória).

## 1. Objetivo

Substituir o Socket.IO do projeto original (conexão sem autenticação,
`broadcast.emit` global, remetente informado pelo cliente) por um
**protocolo de aplicação próprio** sobre WebSocket ([RFC 6455]) que:

1. só aceita conexões de usuários com **sessão válida** (a mesma sessão da
   API HTTP) e vindas da **origem do frontend**;
2. entrega cada mensagem **somente** às conexões inscritas na sala e cujo
   usuário é membro dela;
3. define o **remetente pelo servidor**, a partir da sessão, nunca pelo
   pacote;
4. trata o conteúdo da mensagem (`body`) como **opaco**: o servidor guarda e
   repassa, mas não interpreta nem registra em log. Na Etapa 4 ele passa a
   ser texto cifrado (E2EE) sem mudança no protocolo;
5. resiste a abuso básico: quadros grandes, lixo, inundação, conexões
   mortas e clientes lentos.

O envio de mensagens tem **um único caminho**, o `MSG_SEND` neste
protocolo, que grava no Postgres e depois entrega. O HTTP fica apenas com a
leitura do histórico (`GET /messages/:id`).

[RFC 6455]: https://www.rfc-editor.org/rfc/rfc6455

## 2. Transporte e upgrade

- **Transporte:** WebSocket (RFC 6455) sobre o **mesmo servidor HTTP** da
  API (porta 8000), no caminho **`/ws`**. Biblioteca `ws` (8.x) no servidor.
  Hoje, em `ws://` (sem TLS; ver §9 e §11). Na Etapa 4, `wss://`.
- **Compressão:** `permessage-deflate` **desligado**. Comprimir dados com
  segredos junto de dados controlados pelo atacante abre ataques do tipo
  CRIME/BREACH, e o ganho num chat de texto curto é pequeno.
- **Autenticação:** o cookie de sessão **`sid`** emitido pelo `POST /login`.
  O navegador o envia sozinho no pedido de upgrade (mesma origem do backend
  ou `credentials` do CORS). Não há token separado para o socket: a
  sessão é **uma só** para a API e o tempo real (`createServer.js` passa o
  mesmo middleware e o mesmo store para os dois).

### 2.1 Verificações do upgrade

O servidor processa o evento `upgrade` do HTTP e **só completa o handshake
do WebSocket** se todas as verificações abaixo passarem, nesta ordem. Uma
recusa responde HTTP com corpo JSON genérico `{"message": "..."}` e
`Connection: close`, e fecha o TCP. O socket WebSocket **nunca chega a
abrir**.

| # | Verificação | Falha → resposta HTTP |
|---|---|---|
| 1 | Caminho é exatamente `/ws` | `404 {"message":"Não encontrado"}` |
| 2 | Header `Origin` presente e com origem (esquema + host + porta) **idêntica** à de `CLIENT_URL` | `403 {"message":"Origem não permitida"}` |
| 3 | Cookie `sid` com assinatura válida e sessão existente e não expirada no store do Postgres, com `userId` inteiro | `401 {"message":"Não autenticado"}` |
| 4 | Não houve logout desse usuário **durante** a leitura da sessão (ver §8, corrida TOCTOU) | `401 {"message":"Não autenticado"}` |
| 5 | Usuário não está em quarentena por inundação (60 s após um close 4429) | `429 {"message":"Pacotes demais; tente novamente mais tarde"}` |
| 6 | Usuário tem menos de **5** conexões abertas | `429 {"message":"Conexões demais para este usuário"}` |
| 7 | Servidor tem menos de **1000** conexões abertas | `503 {"message":"Servidor sem vagas de conexão"}` |
| — | Erro inesperado (ex.: store de sessão fora do ar) | `503 {"message":"Erro interno"}` |

Detalhes normativos:

- `Origin` ausente, malformado, ou `CLIENT_URL` não configurado → recusa
  (**falha fechada**). Origens "parecidas" (`http://localhost:3000.evil.example`,
  outra porta, `https` em vez de `http`) são recusadas.
- As verificações 5 a 7 e o registro da conexão rodam **sem `await` entre
  eles** (`handleUpgrade` chama o callback de forma síncrona), então dois
  upgrades simultâneos não furam os limites juntos.
- A conexão conta para os limites 6 e 7 desde o upgrade, **antes** do HELLO.

## 3. Handshake (diagrama de sequência)

Depois do upgrade, a conexão está em `AWAITING_HELLO`. O cliente **DEVE**
enviar `HELLO` em até **5 s**. Até lá, nenhum outro pacote é processado.

```mermaid
sequenceDiagram
    autonumber
    participant C as Cliente
    participant S as Servidor (/ws)
    participant DB as Postgres

    C->>S: POST /login {email, password}
    S->>DB: confere senha, grava sessão
    S-->>C: 200 + Set-Cookie: sid=…; HttpOnly; SameSite=Lax

    C->>S: GET /ws (Upgrade: websocket, Origin, Cookie: sid=…)
    Note over S: caminho /ws? Origin == CLIENT_URL? (403)
    S->>DB: carrega sessão pelo sid (store)
    DB-->>S: { userId } ou nada (401)
    Note over S: logout durante a leitura? (401)<br/>quarentena / 5 por usuário (429)<br/>1000 no total (503)
    S-->>C: 101 Switching Protocols
    Note over C,S: estado AWAITING_HELLO (prazo 5 s → close 4408)

    C->>S: HELLO {v:1, client}
    alt v != 1
        S-->>C: ERROR UNSUPPORTED_VERSION
        S-->>C: close 4426
    else outro pacote antes do HELLO
        S-->>C: ERROR HELLO_REQUIRED
        S-->>C: close 1008
    else ok
        S-->>C: WELCOME {v:1, userId, serverTime, limits}
        Note over C,S: estado READY
    end

    C->>S: SUBSCRIBE {room: 7, id: "s1"}
    S->>DB: SELECT 1 FROM rooms_users WHERE room=7 AND user_id=<sessão>
    S-->>C: SUBSCRIBED {room: 7}  (ou ERROR NOT_MEMBER, ref "s1")

    C->>S: MSG_SEND {room: 7, cid: "c-1", body: "…"}
    S->>DB: INSERT … WHERE EXISTS (membro) ON CONFLICT (user_id, cid) DO NOTHING
    S-->>C: MSG_ACK {cid: "c-1", id: 42, ts}
    S-->>C: MSG_DELIVER {room: 7, id: 42, from: <sessão>, ts, body} (a cada inscrito membro)

    loop a cada 30 s
        S->>C: ping (quadro de controle RFC 6455)
        C-->>S: pong (automático no navegador)
        S->>DB: sessão de cada conexão ainda existe? (senão close 4401)
    end

    C->>S: POST /logout (HTTP)
    S-->>C: close 4401 (todas as conexões do usuário)
```

Máquina de estados de uma conexão:

```
         upgrade aceito
               │
               ▼
      ┌─────────────────┐  5 s sem HELLO ─────────────▶ close 4408
      │ AWAITING_HELLO  │  HELLO com v ≠ 1 ───────────▶ ERROR + close 4426
      │                 │  outro pacote/lixo ─────────▶ ERROR HELLO_REQUIRED + close 1008
      │                 │  HELLO v=1 fora do schema ──▶ ERROR BAD_REQUEST + close 1008
      └────────┬────────┘
               │ HELLO v=1 válido → WELCOME
               ▼
      ┌─────────────────┐  3º pacote inválido ─────────▶ close 1008
      │      READY      │  20ª violação do rate limit ─▶ close 4429 (+ quarentena 60 s)
      │                 │  quadro > 16 KB ─────────────▶ close 1009
      │                 │  logout / sessão encerrada ──▶ close 4401
      │                 │  sem pong no ciclo seguinte ─▶ terminate (TCP derrubado)
      │                 │  buffer de saída > 1 MB ─────▶ terminate
      └─────────────────┘
```

Depois de o servidor iniciar o fechamento, a conexão **descarta** qualquer
quadro que ainda chegue (a `ws` continua emitindo quadros até o fim do
handshake de fechamento, que pode levar até 30 s).

## 4. Formato e tipos de pacote

### 4.1 Envelope

- Cada pacote é **um quadro de texto** WebSocket (UTF-8) contendo **um
  objeto JSON**. Quadros binários são inválidos (`ERROR BAD_REQUEST`).
- Todo pacote tem o envelope:

  ```json
  { "v": 1, "type": "TIPO", "id": "opcional", "...": "campos do tipo" }
  ```

  | Campo | Regra |
  |---|---|
  | `v` | **DEVE** ser o número `1` (versão do protocolo). |
  | `type` | um dos tipos da §4.2, em maiúsculas. |
  | `id` | opcional, só em pacotes do cliente: string de 1 a 64 caracteres escolhida pelo cliente. É devolvida como **`ref`** no `ERROR` (e no `PONG`) que responde àquele pacote. |

- Os pacotes do cliente são validados com **zod** (`clientPacket` em
  `protocol.js`). **Campos não previstos são descartados** antes de chegar
  ao tratamento: um `from`, `user_id` ou `user` enviado pelo cliente é
  simplesmente ignorado.
- Todos os pacotes do servidor levam `v: 1`.

### 4.2 Tipos

Direção: **C→S** (cliente para servidor), **S→C** (servidor para cliente).

| Tipo | Direção | Campos (além de `v`, `type`, `id?`) | Semântica |
|---|---|---|---|
| `HELLO` | C→S | `client?`: string ≤ 64 (nome/versão do cliente, informativo) | Primeiro pacote obrigatório (§3). Repetido depois do WELCOME → `ERROR BAD_REQUEST`. |
| `WELCOME` | S→C | `userId`: inteiro (usuário **da sessão**); `serverTime`: ISO 8601; `limits`: `{ maxPayloadBytes, maxBodyBytes }` | Resposta ao HELLO válido; a conexão passa a READY. |
| `PING` | C→S | — | Teste de vida/latência no nível da aplicação. |
| `PONG` | S→C | `ref?`: o `id` do PING | Resposta ao PING. |
| `SUBSCRIBE` | C→S | `room`: inteiro 1…2147483647 | Pede para receber as mensagens da sala. Só para membros (§7). |
| `SUBSCRIBED` | S→C | `room` | Inscrição aceita. |
| `UNSUBSCRIBE` | C→S | `room` | Cancela a inscrição (idempotente). |
| `UNSUBSCRIBED` | S→C | `room` | Inscrição cancelada, a pedido do cliente **ou pelo servidor** quando o usuário deixou de ser membro da sala (§7). |
| `MSG_SEND` | C→S | `room`: inteiro; `cid`: `[A-Za-z0-9_-]{1,64}`; `body`: string, 1 a **8192 bytes UTF-8**, sem o caractere NUL | Envia uma mensagem. **Não tem campo `from`**. |
| `MSG_ACK` | S→C | `cid`; `id`: inteiro (id da mensagem no banco); `ts`: ISO 8601 | A mensagem foi **gravada**. Correlação pelo `cid`. Reenvio do mesmo `cid` → o mesmo ACK. |
| `MSG_DELIVER` | S→C | `room`; `id`; `from`: inteiro (usuário **da sessão** do remetente, preenchido pelo servidor); `ts`; `body` (como veio) | Mensagem nova na sala. Vai a toda conexão inscrita cujo usuário é membro, **inclusive as do próprio remetente** (o cliente deduplica pelo `id`). |
| `ERROR` | S→C | `code` (§5.1); `message`: texto genérico; `ref?`: o `id` do pacote que causou o erro | Pacote recusado. Salvo os casos da §5.2, a conexão continua aberta. |

Exemplo de troca:

```json
C→S {"v":1,"type":"MSG_SEND","id":"r9","room":7,"cid":"5f0c…","body":"oi"}
S→C {"v":1,"type":"MSG_ACK","cid":"5f0c…","id":42,"ts":"2026-10-28T14:03:11.512Z"}
S→C {"v":1,"type":"MSG_DELIVER","room":7,"id":42,"from":3,"ts":"2026-10-28T14:03:11.512Z","body":"oi"}
```

### 4.3 `body` opaco

O servidor confere **só tipo e tamanho** do `body`: não apara espaços, não
normaliza, não interpreta, **não registra em log** e não compara reenvios.
Uma mensagem só de espaços é aceita como veio. O caractere NUL (`\u0000`) é
recusado porque o Postgres não o aceita em `TEXT` (sem a regra, viraria
erro interno). Na Etapa 4 o `body` será texto cifrado (ex.: base64) e nada
neste protocolo muda.

### 4.4 Idempotência (`cid`)

O `cid` é gerado pelo cliente (o cliente de referência usa um UUID v4) e
identifica **um envio**. Ele é guardado em `messages.cid`, com
`UNIQUE (user_id, cid)`, e a gravação usa `ON CONFLICT DO NOTHING`.
Portanto:

- reenviar o mesmo `cid` na **mesma sala** (ex.: o ACK se perdeu) devolve o
  **mesmo `MSG_ACK`** (mesmo `id` e `ts`), sem gravar nem entregar de novo,
  mesmo que o `body` seja diferente (vale o primeiro; um reenvio cifrado
  de novo na Etapa 4 teria outro texto cifrado);
- reenvios simultâneos gravam uma única vez (o banco resolve a corrida);
- o `cid` é **por remetente**: dois usuários podem usar o mesmo valor;
- **autorização primeiro**: se nada foi gravado, o servidor verifica a
  pertinência à sala **pedida**. Quem não é membro recebe `NOT_MEMBER`,
  haja ou não `cid` repetido; inclusive quem saiu da sala e reenvia
  (não recebe o ACK antigo);
- sendo membro, o mesmo `cid` já usado em **outra sala** → `ERROR CID_REUSED`.

## 5. Erros e códigos de fechamento

### 5.1 Códigos do pacote `ERROR`

| `code` | `message` | Quando | A conexão… |
|---|---|---|---|
| `BAD_REQUEST` | Pacote inválido | JSON inválido, quadro binário, tipo desconhecido, campo fora do schema, `v` ≠ 1 depois do handshake, HELLO repetido, HELLO v=1 malformado | segue aberta; o **3º** pacote inválido fecha com 1008; no handshake, fecha na hora |
| `HELLO_REQUIRED` | Envie HELLO antes de qualquer outro pacote | qualquer pacote (ou lixo) antes do HELLO | fecha com 1008 |
| `UNSUPPORTED_VERSION` | Versão de protocolo não suportada (servidor: 1) | HELLO com `v` ≠ 1 | fecha com 4426 |
| `RATE_LIMITED` | Pacotes demais; aguarde | quadro acima do ritmo (§6). Enviado **só na 1ª violação** de cada sequência, para não amplificar a inundação | segue aberta; na 20ª violação seguida fecha com 4429 |
| `NOT_MEMBER` | Sem acesso a esta sala | SUBSCRIBE ou MSG_SEND para sala da qual o usuário não é membro **ou que não existe** (mesma resposta) | segue aberta |
| `CID_REUSED` | cid já usado em outra sala | MSG_SEND com `cid` que o usuário já usou em outra sala | segue aberta |
| `INTERNAL` | Erro interno | falha inesperada ao tratar o pacote (ex.: banco fora). Num `MSG_SEND`, significa sempre **"não gravado"** (reenviar com o mesmo `cid` é seguro). Uma falha só na **entrega**, depois de gravar e mandar o `MSG_ACK`, não gera ERROR: vai ao log como "falha na entrega" e os inscritos recuperam a mensagem pelo histórico. O log registra o tipo do pacote, o código (SQLSTATE) e a mensagem do erro, nunca o pacote | segue aberta |

As mensagens são fixas e genéricas: nunca ecoam a entrada nem detalham
qual regra falhou.

### 5.2 Códigos de fechamento

Faixa 1000–1015 da RFC 6455 (§7.4.1); 4000–4999 reservada a aplicações. Os
códigos 44xx imitam o status HTTP equivalente para facilitar a leitura.

| Código | Nome (`CLOSE` em `protocol.js`) | Motivo |
|---|---|---|
| **1000** | (normal) | fechamento pedido pelo cliente |
| **1008** | `POLICY_VIOLATION` | pacote antes do HELLO, HELLO malformado ou 3º pacote inválido |
| **1009** | `MESSAGE_TOO_BIG` | quadro acima de `maxPayload` (16 KB); gerado pela própria `ws` antes de acumular o quadro |
| **4401** | `SESSION_ENDED` | logout do usuário (todas as conexões dele), sessão expirada ou apagada do store (validação periódica) |
| **4408** | `HELLO_TIMEOUT` | HELLO não chegou em 5 s |
| **4426** | `UNSUPPORTED_VERSION` | versão do HELLO não suportada |
| **4429** | `RATE_LIMITED` | 20 violações seguidas do rate limit; inicia a quarentena de 60 s |
| (1006 no cliente) | `terminate()` | conexão morta (sem pong) ou cliente lento (buffer de saída > 1 MB): o TCP é derrubado sem handshake de fechamento, porque um close não chegaria |

O cliente **NÃO DEVERIA** reconectar automaticamente após 4401 (precisa de
novo login), 4426 (precisa de atualização) nem 4429 (quarentena). Após 1006
ou 4408, **PODE** reconectar com espera crescente.

## 6. Limites

Valores padrão em `DEFAULT_LIMITS` (`backend/realtime/protocol.js`).
Todos, exceto o tamanho do body, podem ser trocados por instância
(`attachRealtime(server, { ...limites })`), o que os testes usam para
encurtar prazos.

| Limite | Padrão | Efeito ao exceder |
|---|---|---|
| Conexões por usuário (`maxConnectionsPerUser`) | **5** | upgrade recusado com 429 |
| Conexões no total (`maxConnections`) | **1000** | upgrade recusado com 503 |
| Prazo do HELLO (`helloTimeoutMs`) | **5 s** | close 4408 |
| Tamanho do quadro (`maxPayloadBytes`) | **16 KB** (16384 bytes) | close 1009 |
| Tamanho do body (`MAX_BODY_BYTES`, fixo) | **8192 bytes UTF-8** | `ERROR BAD_REQUEST`. Igual ao `CHECK (octet_length(message) BETWEEN 1 AND 8192)` da coluna `messages.message`; não é configurável porque o banco é compartilhado |
| Pacotes inválidos (`maxInvalidPackets`) | **3** por conexão | o 3º fecha com 1008 |
| Rate limit: rajada (`rateBurst`) | **20** quadros | — |
| Rate limit: ritmo (`rateRefillPerSec`) | **10** quadros/s | quadro descartado + `ERROR RATE_LIMITED` (1ª vez) |
| Rate limit: tolerância (`maxRateViolations`) | **20** violações seguidas | close 4429 |
| Quarentena após 4429 (`rateLimitCooldownMs`) | **60 s** | upgrade do mesmo usuário recusado com 429 |
| Heartbeat (`heartbeatIntervalMs`) | **30 s** | sem pong até o ciclo seguinte → `terminate()`; sessão inválida → close 4401 |
| Buffer de saída (`maxBufferedBytes`) | **1 MB** | `terminate()` antes do próximo envio |
| Histórico HTTP (`GET /messages/:id?limit`) | padrão **50**, máximo **100** | `400` |

**Rate limit (token bucket).** Cada conexão tem um balde de 20 fichas,
reposto a 10 fichas/s. **Todo quadro** custa uma ficha: inválidos,
`PING`, e também os quadros antes do HELLO. Sem ficha, o quadro é
descartado **sem ser lido** (nem JSON, nem banco). Quando o balde volta a
ficar cheio (o cliente se acalmou), a sequência de violações zera. Com no
máximo 5 conexões, o teto sustentado por usuário é 5 × 10 = 50 quadros/s.

**Quadro × body.** Um body de 8192 bytes cabe com folga em 16 KB
**se** o JSON não precisar de muitos escapes. Caracteres de controle viram
`\u00XX` (6 bytes cada), então um body cheio deles pode estourar o quadro
(close 1009) mesmo dentro do limite do body. Na prática, texto comum e o
base64 da Etapa 4 não têm esse problema.

## 7. Regras de autorização

A fonte de verdade é o banco (`rooms_users` e `user_sessions`), **nunca** o
que o cliente envia nem estado antigo guardado na conexão.

1. **Identidade = sessão.** O `userId` de uma conexão vem da sessão lida no
   upgrade (`realtime/index.js`) e fica fixo em `conn.userId`. Nenhum
   pacote do cliente carrega identidade: o schema de `MSG_SEND` não tem
   `from`, e campos extras são descartados pelo zod.
2. **Remetente pelo servidor.** O `MSG_DELIVER.from` e o
   `messages.user_id` gravado são sempre `conn.userId`
   (`handlers.js`, `MSG_SEND`).
3. **Inscrição só para membro.** `SUBSCRIBE` consulta
   `rooms_users (room, user_id)`. Sala inexistente e sala alheia recebem o
   **mesmo** `NOT_MEMBER`, para não revelar quais IDs de sala existem.
4. **Nova checagem a cada envio.** `MSG_SEND` grava com
   `INSERT … SELECT … WHERE EXISTS (membro)`: checar e gravar são **uma
   só consulta**, sem janela entre elas. Estar inscrito **não** basta, e
   não é exigido: quem foi removido da sala depois do `SUBSCRIBE` recebe
   `NOT_MEMBER`.
5. **Entrega só a inscritos que ainda são membros.** `MSG_DELIVER` vai
   apenas às conexões do mapa em memória `sala → conexões` daquela sala.
   **Não existe broadcast global.** Antes de entregar, o servidor relê os
   membros da sala: inscrição de quem saiu é desfeita (`UNSUBSCRIBED`) e
   essa conexão não recebe a mensagem.
6. **Logout fecha o canal.** `POST /logout` destrói a sessão e chama
   `onSessionEnd(userId)` (`routes/login.js`), ligado por
   `createServer.js` a `realtime.closeUser`, que fecha com **4401 todas as
   conexões do usuário**, inclusive de outras sessões e as que ainda não
   mandaram HELLO. Um upgrade que estava lendo a sessão durante o logout é
   recusado (contador de revogações, `registry.revokedSince`).
7. **Sessão revalidada periodicamente.** A cada heartbeat (30 s), a sessão
   de cada conexão é relida do store: expirada, apagada do banco (ex.:
   pelo admin ou por logout em outra instância) ou de outro usuário →
   close 4401. Se o store falhar, as conexões são mantidas e o erro é
   registrado (o banco fora já impede gravar e autorizar).
8. **Depois do close, nada é processado.** Quadros que cheguem enquanto o
   fechamento não termina são descartados (`connection.js`, `onFrame`).

## 8. Modelo de ameaças do protocolo

Atores de [`00-modelo-ameacas.md`](00-modelo-ameacas.md): **atacante
externo** (sem conta), **usuário autenticado malicioso** e **site
malicioso** aberto no navegador da vítima. Arquivos de teste em
`backend/tests/ws/` (exceto quando indicado); entre aspas, o nome do teste.

| # | Ameaça | Controle | Teste que prova |
|---|---|---|---|
| T1 | **Cross-Site WebSocket Hijacking**: página de outro site abre `/ws` no navegador da vítima, que manda o cookie sozinho | `Origin` comparado exatamente com `CLIENT_URL`; ausente/parecido → 403 | `upgrade.test.js`: "Origin de outro site → 403, mesmo com cookie válido", "sem Origin → 403", "Origin parecido (sufixo/porta diferente) → 403" |
| T2 | **Conexão sem sessão válida** (item A): sem cookie, cookie forjado, sessão destruída | sessão lida do store no upgrade; falha → 401 e o socket nem abre | `upgrade.test.js`: "sem cookie", "com cookie forjado", "com cookie de sessão destruída (após logout)" |
| T3 | **Ler sala alheia** (item B): inscrever-se ou receber o fluxo de sala da qual não é membro | `SUBSCRIBE` só para membro; entrega só a inscritos que ainda são membros; sem broadcast | `subscribe.test.js`: "B não consegue SUBSCRIBE em sala da qual não é membro"; `msgSend.test.js`: "B inscrito na sala X NÃO recebe mensagens da sala Y", "quem foi removido da sala deixa de receber, mesmo ainda inscrito" |
| T4 | **Forjar o remetente** (item C) | schema sem `from`; remetente = `conn.userId` | `msgSend.test.js`: "campo from forjado é ignorado: a mensagem sai com o usuário da sessão" |
| T5 | **Postar em sala alheia / depois de ser removido** | pertinência checada na mesma consulta que grava, a cada `MSG_SEND` | `msgSend.test.js`: "não membro: ERROR NOT_MEMBER e nada é gravado", "MSG_SEND de quem foi removido da sala (já inscrito) é rejeitado" |
| T6 | **Enumerar salas** pelo tipo de erro | sala inexistente e alheia → mesmo `NOT_MEMBER` | `subscribe.test.js`: "sala inexistente recebe o mesmo erro (não revela quais IDs existem)"; `msgSend.test.js`: "sala inexistente recebe o mesmo NOT_MEMBER" |
| T7 | **Payload gigante** (memória) | `maxPayload` 16 KB → 1009 antes de acumular; body ≤ 8192 bytes | `frames.test.js`: "quadro acima do limite → close 1009", "…antes do HELLO também → close 1009"; `msgValidation.test.js` |
| T8 | **Lixo / fuzzing** e injeção pelos campos | zod em todo pacote; 3º inválido → 1008; consultas parametrizadas | `frames.test.js`: "reincidência: no 3º pacote inválido → ERROR e close 1008"; `msgValidation.test.js`: "a tabela messages continua intacta após a tentativa de injeção" |
| T9 | **Inundação** (cada pacote custa banco) | token bucket por conexão → `RATE_LIMITED`/4429; quarentena de 60 s contra reconexão; ≤ 5 conexões por usuário | `rateLimit.test.js`: "inundação persistente → close 4429", "o usuário derrubado por inundação não reabre conexão durante a quarentena (429)"; `upgrade.test.js`: "por usuário: …recusada com 429" |
| T10 | **Segurar recursos**: conectar e não falar; sumir sem fechar o TCP | prazo do HELLO (4408); heartbeat de 30 s com `terminate()` | `hello.test.js`: "sem HELLO dentro do prazo → close 4408"; `heartbeat.test.js`: "cliente que não responde ao ping (conexão morta) é encerrado e sai do registro" |
| T11 | **Cliente lento** de propósito (buffer de saída cresce no servidor) | `bufferedAmount` > 1 MB → `terminate()` | `backpressure.test.js`: "cliente com buffer de saída acima do limite é desconectado na próxima entrega" |
| T12 | **Reenvio duplicado** (ou replay do mesmo pacote pelo próprio usuário) | `UNIQUE (user_id, cid)` + `ON CONFLICT DO NOTHING` | `idempotency.test.js`: "reenvio do mesmo cid não duplica…", "reenvios simultâneos do mesmo cid gravam uma única vez" |
| T13 | **Socket sobrevive ao logout** (computador compartilhado) ou à expiração da sessão | logout → 4401 em todas as conexões; nova checagem da sessão no heartbeat; quadros após o close descartados | `logout.test.js`: "após logout, a conexão aberta é fechada com 4401", "quadro que chegue depois do close (cliente que ignora o fechamento) não é processado"; `heartbeat.test.js`: "sessão apagada do store fora do logout → close 4401…", "sessão expirada → close 4401" |
| T14 | **Corrida upgrade × logout (TOCTOU)**: o upgrade lê a sessão válida, o logout acontece, o upgrade completa depois do `closeUser` | contador de revogações por usuário, conferido depois de ler a sessão e antes de `handleUpgrade` (sem `await` entre os dois) → 401 | `logout.test.js`: "upgrade em andamento durante o logout não sobrevive a ele (corrida TOCTOU)" (reproduzido antes da correção) |
| T15 | **Vazamento do body / cookie em logs** (admin lendo logs) | nenhum caminho registra pacote, body ou cabeçalhos; erros registram só o tipo do pacote | `logging.test.js` (3 testes, validados por mutação) |
| T16 | **CRIME/BREACH** via compressão | `permessage-deflate` desligado | — (configuração em `realtime/index.js`) |

Ameaças **não** cobertas nesta etapa estão na §9.

## 9. Limitações conhecidas

1. **Sem TLS nem E2EE (Etapa 4).** Hoje o tráfego é `ws://` e `http://`:
   na rede passam em claro a senha do login, o cookie `sid` (que permite
   sequestrar a sessão), todos os pacotes e o `body` (ver §11). O banco
   guarda o `body` em claro, então o admin lê tudo. A Etapa 4 troca para
   `wss://` e cifra o `body` no cliente, sem mudar o protocolo.
2. **Metadados visíveis ao servidor**, mesmo depois da E2EE: quem está
   conectado, em que salas se inscreve, quem envia para qual sala, quando,
   com que frequência e o tamanho de cada `body`. O `cid` gravado em
   `messages` é mais um metadado. É uma limitação de qualquer arquitetura
   cliente-servidor ([`00-modelo-ameacas.md`](00-modelo-ameacas.md) §4);
   minimizar retenção e logs é a Etapa 5.
3. **Body sem integridade fim a fim.** O servidor (ou o admin) pode alterar,
   reordenar, descartar ou reinjetar mensagens (o `from` é definido por ele).
   A autenticidade do conteúdo entre usuários depende da E2EE autenticada
   da Etapa 4.
4. **Estado em memória, instância única.** Inscrições (`sala → conexões`),
   contagem de conexões, baldes do rate limit, quarentenas e o contador de
   revogações vivem no processo (`realtime/registry.js`). Com mais de uma
   instância, uma mensagem gravada numa instância não chega aos inscritos
   da outra, o limite de 5 conexões vale por instância, e o logout só fecha
   na hora as conexões da instância que o recebeu (as demais, no próximo
   heartbeat, em até 30 s). Escalar exige um barramento compartilhado (ex.:
   `LISTEN/NOTIFY` do Postgres ou Redis). Reiniciar o servidor derruba
   todas as conexões, e os clientes precisam se inscrever de novo.
5. **Sem entrega offline nem retomada.** Quem está desconectado não recebe
   nada pelo socket. Ao reconectar, o cliente busca o histórico em
   `GET /messages/:id` (as mais recentes, paginando para trás com
   `before`). Não há "desde o id N" nem confirmação de leitura pelo
   protocolo.
6. **Envios em andamento no fechamento.** Um `MSG_SEND` que já estava
   gravando quando o logout (ou um 4429) fechou a conexão é gravado e
   entregue aos inscritos, porque foi enviado enquanto a sessão valia. O
   remetente, porém, não recebe o `MSG_ACK` (a conexão já não está
   aberta) e deve tratar o envio como não confirmado.
7. **Expiração da sessão detectada em até 30 s.** Sessão apagada ou
   expirada fora do logout só fecha o socket no próximo heartbeat. Se o
   store estiver fora do ar, as conexões são mantidas (escolha por
   disponibilidade; o banco fora já impede gravar e autorizar).
8. **Saída da sala percebida na próxima mensagem.** Quem é removido de uma
   sala continua no mapa de inscrições até a próxima entrega naquela sala,
   quando é desinscrito (`UNSUBSCRIBED`) **sem** receber a mensagem. Não
   há rota de remoção de membros ainda (os testes apagam direto no banco).
9. **Logout fecha todas as conexões do usuário**, inclusive de outros
   dispositivos com sessões ainda válidas (como pede a especificação).
   Esses clientes podem reconectar com o próprio cookie.
10. **Rate limit por conexão.** Com 5 conexões, um usuário sustenta até
   50 quadros/s. Um usuário em quarentena só bloqueia a si mesmo.
11. **Uma única origem** (`CLIENT_URL`). Clientes fora do navegador (como
    o `ws-client.js`) declaram o `Origin` que quiserem. A checagem protege o
    navegador da vítima, não autentica o programa cliente.
12. **Escape JSON × tamanho do quadro**: um body cheio de caracteres de
    controle pode estourar 16 KB mesmo abaixo de 8192 bytes (§6).

## 10. Mudanças de contrato para o frontend

Complementa a §5 de [`02-autenticacao-autorizacao.md`](02-autenticacao-autorizacao.md).

| Antes (Etapa 2) | Agora (Etapa 3) |
|---|---|
| Socket.IO (`socket.io-client`), sem autenticação, evento global | **WebSocket nativo** do navegador em `ws://<backend>/ws` (Etapa 4: `wss://`). Remover a dependência `socket.io-client`. |
| `POST /messages { room, message }` → `201` | **Removido**: com sessão responde `404`, sem sessão `401`. Enviar com `MSG_SEND` pelo socket e tratar o `MSG_ACK`. |
| Mensagem nova chegava por `broadcast` de todas as salas | Chega como `MSG_DELIVER` **só** das salas em que o cliente fez `SUBSCRIBE`. |
| Remetente informado pelo cliente | Ignorado. Use `MSG_DELIVER.from` (definido pelo servidor). |
| `GET /messages/:id` devolvia todas as mensagens | **Paginado**: `?limit=` (1 a 100, padrão 50) e `?before=<id>`; devolve as `limit` mais recentes com id menor que `before`, **em ordem cronológica**. Valores fora da regra → `400`. Campos de cada item inalterados: `username`, `userid`, `message`, `dtmessage`, `idmessage`, `roomname`, `roomid` (minúsculas, como o Postgres devolve). |
| Mensagem até 500 caracteres | `body` até **8192 bytes UTF-8**, sem trim no servidor (§4.3). |

Roteiro mínimo do cliente:

```js
const ws = new WebSocket(`${BACKEND_WS}/ws`);          // cookie sid vai sozinho
const send = (p) => ws.send(JSON.stringify({ v: 1, ...p }));
ws.onopen = () => send({ type: "HELLO", client: "web/1.0" });   // em até 5 s
ws.onmessage = ({ data }) => {
  const p = JSON.parse(data);
  if (p.type === "WELCOME") send({ type: "SUBSCRIBE", room: salaAtual, id: "sub" });
  if (p.type === "MSG_DELIVER") mostrar(p);           // deduplicar por p.id
  if (p.type === "MSG_ACK") confirmar(p.cid, p.id);
  if (p.type === "ERROR") tratarErro(p.code, p.ref);
};
// enviar: send({ type: "MSG_SEND", room, cid: crypto.randomUUID(), body: texto });
// reenviar com o MESMO cid se o MSG_ACK não chegar (idempotente).
ws.onclose = ({ code }) => {
  if (code === 4401) irParaLogin();                   // não reconectar
  else if (code !== 4426 && code !== 4429) reconectarComEspera();
};
```

Observações para o frontend:

- O navegador responde aos **pings de controle** sozinho; o `PING` do
  protocolo é opcional.
- Ao reconectar, refazer `HELLO` e os `SUBSCRIBE`, e buscar o histórico
  pelo HTTP para cobrir o intervalo desconectado (não há entrega offline).
- **Cookie entre sites:** o `sid` é `SameSite=Lax`. Frontend e backend
  precisam ser o **mesmo site** (ex.: `localhost:3000` e `localhost:8000`,
  ou subdomínios do mesmo domínio); senão o navegador não envia o cookie
  no upgrade e a resposta é `401`.
- O `Origin` da página precisa ser exatamente o `CLIENT_URL` do backend.

## 11. Captura no Wireshark

Base de comparação para a Etapa 4: o que um atacante na rede vê **hoje**.

### 11.1 Passos

1. Suba o backend: `docker compose up --build` (porta 8000 publicada).
   Crie dois usuários e uma sala, por exemplo com `curl` ou pelo frontend,
   e anote o ID da sala.
2. Abra o Wireshark e escolha a interface:
   - **`lo` (loopback)**: cliente e `docker compose` na mesma máquina. O
     tráfego cliente → `localhost:8000` passa pelo `docker-proxy` no
     loopback;
   - **`docker0` / `br-…`** (bridge do Compose): o trecho proxy → container;
   - **`any`**: as duas de uma vez (os pacotes aparecem duplicados).
3. Comece a captura, de preferência só da porta do app: filtro de captura
   `tcp port 8000`.
4. Em dois terminais (a partir de `backend/`), rode o cliente de referência:

   ```bash
   CHAT_PASSWORD='senha-da-alice' node tools/ws-client.js --email alice@example.com --room 1
   CHAT_PASSWORD='senha-do-bob'   node tools/ws-client.js --email bob@example.com   --room 1
   ```

   Digite uma mensagem num deles e encerre com Ctrl+D.
5. Filtro de exibição: **`websocket`** (só quadros WebSocket) ou
   `http || websocket` (login, upgrade e quadros). Se o Wireshark não
   reconhecer o HTTP na porta 8000: botão direito → *Decode As…* → TCP port
   8000 → HTTP. A partir do `101 Switching Protocols`, ele passa a decodificar
   os quadros como WebSocket.
6. Em um quadro, veja *Line-based text data* / *JavaScript Object
   Notation*. Os quadros do cliente são **mascarados** (RFC 6455 §5.3), mas
   a máscara viaja junto e não é sigilo: o Wireshark mostra o conteúdo
   desmascarado (*Unmasked data*). *Follow → TCP Stream* mostra a conversa
   inteira.

### 11.2 O que se vê hoje (sem TLS, sem E2EE)

Tudo em claro:

| Momento | Visível na captura |
|---|---|
| `POST /login` | e-mail e **senha** no corpo JSON |
| Resposta do login | `Set-Cookie: sid=s%3A…` (**o cookie basta para sequestrar a sessão** até o logout ou 8 h) |
| `GET /ws` (upgrade) | `Cookie: sid=…`, `Origin`, `Sec-WebSocket-Key` |
| `WELCOME` | `userId` do usuário |
| `SUBSCRIBE` / `SUBSCRIBED` | ID da sala |
| `MSG_SEND` / `MSG_DELIVER` | **o texto da mensagem (`body`)**, `room`, `from`, `ts`, `cid` |
| a cada 30 s | quadros de controle *Ping* / *Pong* |

Ou seja, o protocolo da Etapa 3 resolve **quem pode** conectar, ler e
enviar, mas **não** esconde nada de quem escuta a rede (item G) nem do
servidor (item F).

### 11.3 Comparação com a Etapa 4 (preencher)

| Momento | Etapa 3 (hoje) | Etapa 4 (`wss://` + E2EE) |
|---|---|---|
| `POST /login` | senha em claro | |
| Cookie `sid` | em claro | |
| Upgrade `/ws` | cabeçalhos em claro | |
| `MSG_SEND.body` | texto em claro | |
| `MSG_DELIVER.body` | texto em claro | |
| Metadados (sala, remetente, horário, tamanho) | em claro na rede | |
| Coluna `messages.message` no banco | texto em claro | |
| Captura (arquivo `.pcapng`) | | |

## 12. Testes

```bash
docker compose -f docker-compose.test.yml up -d --wait   # Postgres de teste (porta 5433)
cd backend && npm test                                   # 24 suítes, 264 testes, ~25 s
```

Os testes do protocolo sobem o servidor HTTP **de verdade** numa porta
livre (`tests/ws/helpers.js`) e conversam com ele por WebSocket real. Os
prazos (HELLO, heartbeat, quarentena) são encurtados por opção. Cada
controle teve o teste escrito antes e visto falhando. Os que já passavam
contra o código existente (registro de logs, CID_REUSED e as lacunas
apontadas pela revisão: prazo do HELLO cancelado, upgrades simultâneos,
`CLIENT_URL` ausente, SUBSCRIBE em conexão fechada, isolamento X/Y) foram
validados por **mutação**: a quebra proposital do código os fez falhar.

| Arquivo | Testes | O que prova |
|---|---|---|
| `tests/ws/upgrade.test.js` | 17 | upgrade sem cookie, com cookie forjado, de sessão destruída ou expirada → 401 sem abrir o socket; `Origin` alheio, ausente, `null` ou parecido → 403, e `CLIENT_URL` ausente → 403 (falha fechada); outro caminho → 404; 5 por usuário → 429; total → 503; upgrades **simultâneos** não furam os limites |
| `tests/ws/hello.test.js` | 13 | WELCOME com o usuário da sessão; HELLO aceito cancela o prazo; sem HELLO em 5 s → 4408; versão errada, `v` texto ou ausente → 4426; pacote, JSON inválido ou binário antes do HELLO → 1008; HELLO fora do schema → 1008; PING → PONG |
| `tests/ws/subscribe.test.js` | 10 | SUBSCRIBE só para membro; sala inexistente = alheia; UNSUBSCRIBE; fechar remove as inscrições; conexão que fecha durante o SUBSCRIBE não fica inscrita; sala inválida → BAD_REQUEST |
| `tests/ws/msgSend.test.js` | 11 | `from` forjado ignorado (renasce de `messageSender.test.js`); entrega só a inscritos da sala (X não recebe Y, nem quem é membro de Y mas só inscrito em X); não membro e removido → NOT_MEMBER sem gravar; removido deixa de receber (UNSUBSCRIBED) |
| `tests/ws/idempotency.test.js` | 9 | mesmo `cid` não duplica (mesma conexão, outra conexão, simultâneo); `cid` por usuário; outra sala → CID_REUSED; NOT_MEMBER tem precedência sobre o `cid` |
| `tests/ws/msgValidation.test.js` | 18 | body vazio, acima de 8192 bytes, não-string, ausente, com NUL; sala como texto com SQL injection, ausente ou acima do INTEGER; `cid` inválido → ERROR sem fechar e sem gravar; body com exatamente 8192 bytes (ASCII e multibyte) aceito (renascem de `validation.test.js`) |
| `tests/ws/frames.test.js` | 9 | quadro > 16 KB → 1009 (também antes do HELLO); JSON inválido, binário e tipo desconhecido → ERROR; 3º inválido → 1008; NOT_MEMBER não conta |
| `tests/ws/rateLimit.test.js` | 7 | token bucket: excesso → ERROR único; inundação → 4429; acalmar zera; quarentena de 60 s → 429 no upgrade |
| `tests/ws/logout.test.js` | 5 | logout → 4401 em todas as conexões do usuário; outros não são afetados; quadros pós-close descartados; corrida upgrade × logout → 401 |
| `tests/ws/heartbeat.test.js` | 6 | ping de controle periódico; conexão morta encerrada; sessão apagada ou expirada → 4401 |
| `tests/ws/errorPaths.test.js` | 6 | falha na entrega depois do ACK não vira ERROR; log com código; erro de protocolo da ws registrado sem conteúdo; falha depois do 101 derruba o socket sem HTTP no fluxo; store fora no heartbeat mantém as conexões; falha ao derrubar sockets não impede o 204 do logout |
| `tests/ws/backpressure.test.js` | 3 | buffer de saída > limite → desconecta; no limite → entrega normal |
| `tests/ws/logging.test.js` | 3 | nenhum log (console nem stdout/stderr) contém body ou cookie: fluxo normal, erros, erro interno, payload gigante, falha no upgrade |
| `tests/messagesHistory.test.js` | 13 | `POST /messages` → 404; histórico paginado (`limit`, `before`, padrão 50, máximo 100, entradas inválidas → 400); coluna aceita até 8192 bytes e recusa acima |
| `tests/tools/wsClient.test.js` | 11 | o cliente de referência (processo real) envia, recebe, faz logout ao sair (também após upgrade recusado), avisa logout que falhou, não fica pendurado com envios descartados ou fechamento 4429, e resiste a pacote inválido do servidor |

Testes anteriores ajustados por causa da remoção do `POST /messages`:
`messageSender.test.js` (removido; renasce em `msgSend.test.js`), os casos
de mensagem de `validation.test.js` (renascem em `msgValidation.test.js`),
"não membro posta" de `requireRoomMember.test.js` (renasce em
`msgSend.test.js`), e `hygiene.test.js` (grava a mensagem direto no banco).
