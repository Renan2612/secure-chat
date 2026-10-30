# Etapa 5 — Privacidade: mensagens efêmeras, nome cifrado, CSRF e metadados

A E2EE das Etapas 4b-1 e 4b-2 esconde o **conteúdo**. Esta etapa reduz o
que sobra: quanto tempo as mensagens ficam, o nome das salas, o que os
componentes registram em log e a precisão dos horários. Formatos
criptográficos em [`05-e2ee.md`](05-e2ee.md) §12; contrato do `/ws` em
[`03-protocolo.md`](03-protocolo.md).

## 1. O que mudou

| Item | Antes | Agora | Prova |
|---|---|---|---|
| Expiração | mensagens para sempre | envelope **v2** `{v:2,kv,iv,ct,sig,exp}`; `exp` (segundos Unix UTC ou `null`) vai no AAD e na assinatura; o servidor exige `agora + 30 s − 5 min ≤ exp ≤ agora + 7 d + 5 min` (e nunca já vencido); o histórico e a entrega ignoram as vencidas; um job apaga do banco a cada 60 s | `tests/e2ee/ephemeral.test.js`, `tests/ws/ephemeral.test.js`, `scripts/verify-e2ee.sh` (5) |
| Retenção da sala | — | `PUT /rooms/:id/retention` (só o dono; 60 s a 7 d ou `null`); vale para as mensagens **futuras**; com retenção, `exp` é obrigatório (`RETENTION_REQUIRED`) e limitado (`TTL_INVALID`); `ROOM_EVENT RETENTION_CHANGED` | `tests/ws/ephemeral.test.js`, `tests/roomSettings.test.js` |
| Nome da sala | `rooms.name` em claro; busca por nome | `rooms.name_env`, **assinado pelo dono** (`seq` crescente) e cifrado com a chave da sala (AAD `["room-name", sala, kv]`); vem na v1; cada rotação recifra o mesmo conteúdo assinado (ou `null`); `PUT /rooms/:id/name` (dono, chave atual); o cliente só mostra o nome assinado pelo dono atual, senão "Sala #id"; `POST /checkRoomExists` removida | `tests/roomSettings.test.js` (nenhuma coluna tem o nome), `tests/e2ee/roomNameSigned.test.js`, `verify-e2ee.sh` |
| CSRF | só `SameSite=Strict` | toda requisição POST/PUT/PATCH/DELETE exige `Origin` igual a `CLIENT_URL` (403) e, com corpo, `Content-Type: application/json` (415) — inclusive `/login` e `/register` | `tests/csrf.test.js` |
| Banimentos | só o banco | `GET /rooms/:id/bans` e `DELETE /rooms/:id/bans/:userId` (só o dono; respostas genéricas) | `tests/roomSettings.test.js` |
| Horários | `dt_message` e `ts` em milissegundos | só o **minuto** (`date_trunc` + `CHECK`); a ordem vem do `id`; o cliente arredonda o `exp` para **cima** no minuto (senão o `exp` revelaria o segundo do envio) | `tests/ws/ephemeral.test.js` |
| Logs | Docker sem rotação | `json-file` com `max-size 1m`, `max-file 3` em todos os serviços; Postgres sem `log_statement`, sem `log_connections`/`log_disconnections`, erros em `terse` e sem o comando que falhou | `docker-compose.yml`, `tests/privacyLogs.test.js`, `verify-e2ee.sh` (logs) |

## 2. Inventário: o que cada componente registra e por quanto tempo

| Componente | O que registra | O que **não** registra | Onde fica | Por quanto tempo |
|---|---|---|---|---|
| Backend (Node) | início do servidor; avisos `[PERIGO]` das flags de teste; erros internos: método, rota **declarada** (`/rooms/:id`, não o id), SQLSTATE, metadados de schema do pg (constraint, tabela) e a pilha; no `/ws`, `user=<id>` em erro de protocolo e o id da mensagem numa falha de entrega | corpo das requisições, cabeçalhos (cookie), `err.detail` do pg (valores das colunas), IP, e-mail, body das mensagens, nome de sala, contagens do expurgo | stdout/stderr → log do Docker | até 3 × 1 MB por contêiner (o mais antigo é apagado) |
| Caddy | erros e eventos do próprio Caddy (certificados da CA local, recarga de config) | **não há log de acesso** (sem a diretiva `log` no Caddyfile): nenhum IP, caminho, user-agent ou status por requisição | stdout → log do Docker | 3 × 1 MB |
| Postgres | início/parada, checkpoints, mensagens de ERRO **sem DETAIL** e sem o comando (`log_error_verbosity=terse`, `log_min_error_statement=panic`) | comandos (`log_statement=none`), conexões e desconexões (com IP), valores das linhas | stderr → log do Docker | 3 × 1 MB |
| Postgres (dados) | tabelas: usuários (nome, e-mail, hash bcrypt), sessões (id do usuário, expiração), salas (`name_env` cifrado, dono, retenção), vínculos, chaves públicas, wraps, mensagens (envelope cifrado, remetente, sala, minuto, `expires_at`) | texto das mensagens, nome das salas, chaves privadas, chaves de sala | volume `db_data` | até apagar; mensagens com `exp`: até o expurgo (≤ 60 s depois de vencer) — mais as páginas antigas até o `VACUUM` (§4) |
| Docker | os logs acima (`json-file`), metadados dos contêineres | — | `/var/lib/docker/containers/*/…-json.log` (precisa de root para ler) | rotação 3 × 1 MB |
| Cliente de referência (`ws-client`) | keystore e trust store **cifrados** (fora de repositórios git, 0600) | texto das mensagens (só na tela; a efêmera é esquecida ao vencer) | `~/.config/secure-chat/` | até o usuário apagar |

O teste `backend/tests/privacyLogs.test.js` captura tudo o que o backend
escreve num fluxo completo — com falha do banco no meio de um cadastro,
e-mail repetido, JSON malformado, nome em claro recusado, CSRF, texto puro
no `/ws`, quadro inválido e upgrade de outra origem — e falha se aparecer
e-mail, senha, cookie, IP (qualquer IPv4), body ou nome de sala. O
`scripts/verify-e2ee.sh` faz o mesmo nos logs **reais** dos três contêineres
(e-mails, nome da sala, marcadores, cookie e o IP com que os clientes chegam
ao proxy).

## 3. O que o servidor ainda vê

Mesmo com tudo acima, quem controla o servidor (ou lê o banco) sabe:

- **quem** está em cada sala, quem criou, quem é o dono, quem foi banido;
- **quem** mandou cada mensagem, em **qual** sala, e o **minuto**;
- o **tamanho** de cada mensagem, arredondado para blocos de 128 bytes (padding);
- o `exp` de cada mensagem (arredondado ao minuto) e a retenção da sala;
- o **IP** de cada conexão, no momento em que ela acontece (não é gravado,
  mas o processo o recebe; o rate limit o guarda em memória por 15 min);
- o e-mail e o nome de exibição de cada conta; quando cada sessão expira.

Esconder isso exigiria outra arquitetura (mixnets, PIR, contas anônimas,
padding de tráfego) e está fora do escopo do projeto.

## 4. Limites honestos

1. **O servidor pode simplesmente não apagar.** A expiração é uma promessa
   de um servidor honesto. Um servidor malicioso guarda o envelope; o que
   o protege é a E2EE (sem a chave, o envelope não abre). O `verify-e2ee.sh`
   prova que **este** servidor apaga (e a mutação `server-no-purge` prova que
   o script percebe quando não apaga).
2. **Cópias e capturas de tela**: quem recebeu pode copiar, fotografar ou
   rodar um cliente modificado que não esquece. A expiração não volta no
   tempo.
3. **Backups e páginas do Postgres**: o `DELETE` marca a linha como morta;
   ela continua no arquivo até o `VACUUM` reaproveitar a página (e no WAL),
   e para sempre num backup feito antes. Mesmo assim, só envelope cifrado.
4. **Relógio do cliente**: quem decide o `exp` é o remetente; o servidor
   limita com o próprio relógio (tolerância de 5 min). Um receptor com o
   relógio atrasado mostra a mensagem por mais tempo; adiantado, a descarta
   antes. O receptor também descarta `exp` acima de 7 d + 5 min.
5. **O removido retém o que recebeu**: quem saiu ou foi removido continua
   com as chaves antigas e com o que já baixou (a rotação só protege o que
   vem depois).
6. **Nome da sala** — brecha **FECHADA** (achado da revisão automática do
   commit ab4bf1b: um membro que não era o dono mudava o nome **trocando a
   chave**, porque a rotação traz o nome recifrado e o servidor não o lê).
   Agora o nome é assinado pelo dono (`{name, seq, ownerId, sig}` dentro do
   texto cifrado; [`05-e2ee.md`](05-e2ee.md) §12.2): quem rotaciona só
   recifra o conteúdo assinado, e os clientes recusam o que não tem a
   assinatura do dono atual. Testes que provam:
   - `tests/e2ee/roomNameSigned.test.js`: não-dono assina com a própria
     chave, forja o `ownerId` do dono, adultera a assinatura, faz rollback
     de `seq`, repete o `seq` com outro nome; o servidor troca o `name_env`
     pelo de outra sala (o AAD amarra a sala); troca de dono com
     re-assinatura `seq + 1`; rotação sem nome cai no fallback; não-dono
     publica `seq` = 2³¹ − 1 para o dono nunca mais renomear (o `seq` visto
     e não verificado é ignorado no estouro; achado da revisão automática);
   - `tests/tools/wsClientPrivacy.test.js`: no `ws-client`, não-dono
     rotaciona com outro nome → rejeitado, com o aviso "alterado por quem
     não é o dono"; o novo dono re-assina ao receber `OWNER_CHANGED`;
     rotação sem conteúdo válido → `name_env` vazio e "Sala #id (nome não
     verificado)";
   - com a verificação da assinatura desligada de propósito, 5 desses
     testes de ataque falham (mutação conferida à mão).

   Limites que continuam:
   - **o servidor afirma quem é o dono** (`ownerId` no `GET /rooms`): um
     servidor malicioso pode dizer que um cúmplice é o dono, e então o nome
     assinado por ele vale. Cobertura real só com a lista de membros (e o
     cargo) assinada, já pendente desde a 4b-2;
   - **o dono malicioso renomeia** à vontade (é o cargo dele);
   - um cliente que **nunca viu** um `seq` maior aceita um nome antigo
     válido do mesmo dono (o rollback só é detectado em relação ao que o
     cliente já viu);
   - **o nome é metadado cifrado, não anônimo**: o servidor não o lê, mas
     sabe que a sala tem um nome, quando ele muda e o tamanho em blocos
     de 128 bytes;
   - quem saiu continua com os nomes que já leu.
7. **Retenção não é retroativa**: mudar a retenção não apaga nem encurta o
   que já está gravado (o `exp` de cada mensagem foi assinado pelo remetente).
8. **Precisão de tempo**: o minuto ainda permite correlacionar conversas
   com outros eventos; e o IP de cada conexão continua visível ao servidor
   no momento em que ela acontece.

## 5. Como verificar

```bash
cd backend && npx jest --runInBand tests/csrf.test.js tests/roomSettings.test.js \
  tests/privacyLogs.test.js tests/ws/ephemeral.test.js tests/e2ee/ephemeral.test.js \
  tests/tools/wsClientPrivacy.test.js
# stack no ar:
scripts/verify-e2ee.sh                          # deve passar
MUTATION=server-no-purge scripts/verify-e2ee.sh # deve FALHAR (servidor não apaga)
```

O esquema mudou nesta etapa (envelope v2, `name_env`, `expires_at`,
`retention_seconds`): o banco de desenvolvimento precisa ser recriado.
`docker compose --env-file backend/.env down -v` apaga **todos** os volumes
(inclusive a CA local do Caddy: depois, `scripts/export-ca.sh` e importe a CA
de novo). Para manter a CA, apague só o volume do banco:
`docker compose --env-file backend/.env down && docker volume rm secure-chat_db_data`.
