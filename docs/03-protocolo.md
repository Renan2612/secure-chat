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
- o mesmo `cid` em **outra sala** → `ERROR CID_REUSED`;
- o reconhecimento de reenvio também exige ser membro: quem saiu da sala
  recebe `NOT_MEMBER`, não o ACK antigo.

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
| `INTERNAL` | Erro interno | falha inesperada ao tratar o pacote (ex.: banco fora). O log registra só o tipo do pacote e a mensagem do erro | segue aberta |

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

## 8. Modelo de ameaças do protocolo

## 9. Limitações conhecidas

## 10. Mudanças de contrato para o frontend

## 11. Captura no Wireshark

## 12. Testes
