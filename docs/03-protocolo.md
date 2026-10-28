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

## 5. Erros e códigos de fechamento

## 6. Limites

## 7. Regras de autorização

## 8. Modelo de ameaças do protocolo

## 9. Limitações conhecidas

## 10. Mudanças de contrato para o frontend

## 11. Captura no Wireshark

## 12. Testes
