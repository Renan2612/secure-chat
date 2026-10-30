# Etapa 5 — andamento

Plano: [`plano-etapa5.md`](plano-etapa5.md). Para retomar: ler este arquivo e o plano.

## Parte A — privacidade (backend e ws-client)

Feito:
- [x] Revisão de segurança do 4b048b3 (sem correção urgente; rollback do trust store registrado como limite) — `docs/05-e2ee.md` §12.3
- [x] A1 envelope v2 `{v:2,kv,iv,ct,sig,exp}`, AAD `[2,roomId,kv,senderId,cid,exp]`; cliente descarta vencida (`expired`) e `exp` acima do teto
- [x] A1 servidor: limites do `exp` (`TTL_INVALID`), retenção por sala (`PUT /rooms/:id/retention`, `RETENTION_REQUIRED`, `ROOM_EVENT RETENTION_CHANGED`), `messages.expires_at` com `CHECK` coerente com o envelope
- [x] A1 expurgo a cada 60 s (`PURGE_INTERVAL_MS`), histórico e `MSG_DELIVER` ignoram vencidas; relógio de teste (`SIGUSR2`) e mutação sem expurgo só com flag exata
- [x] A2 CSRF: `Origin` = `CLIENT_URL` e JSON em POST/PUT/PATCH/DELETE (inclusive login)
- [x] A2 `GET /rooms/:id/bans` e `DELETE /rooms/:id/bans/:userId` (só o dono)
- [x] A3 nome da sala cifrado (`name_env`), obrigatório na v1 e em cada rotação; `PUT /rooms/:id/name`; `GET /rooms` com `nameEnv`; `checkRoomExists` removida (A3 **não** foi pulado)
- [x] A4 `docs/06-privacidade.md` (inventário, o que o servidor ainda vê, limites); compose com `json-file` 3 × 1 MB; Postgres sem `log_statement`/`log_connections`, erros `terse`; `dt_message`/`ts` no minuto; teste de varredura de logs
- [x] A5 ws-client: `/ttl`, `/retention`, `/bans`, `/unban`, `/rename`; mensagem com `exp` mostrada com a expiração e esquecida ao vencer
- [x] A5 `scripts/verify-e2ee.sh` estendido: efêmera some do histórico e do banco (relógio de teste), nome da sala invertido para "não aparece em claro", varredura dos logs dos contêineres, mutação `server-no-purge`
- [x] Docs: 05 §12, 03, 06, 01, README
- [x] Brecha do nome da sala FECHADA: nome assinado pelo dono `{name, seq, ownerId, sig}`, maior seq no keystore, rotação recifra o mesmo conteúdo (ou `null`), `ROOM_EVENT OWNER_CHANGED` e re-assinatura `seq + 1` pelo novo dono — `docs/05` §12.2, `docs/06` §4.6
- [x] Achados da revisão automática no seq do nome (estouro e janela de 1000 para o seq não verificado), corrigidos com teste de ataque
- [x] Suíte completa: 761 passaram, 1 pulado (e2e opcional)
- [x] Banco de desenvolvimento recriado (só o volume `secure-chat_db_data`; CA do Caddy mantida)
- [x] `scripts/verify-e2ee.sh`: normal → saída 0 (todas as provas); `MUTATION=server-no-purge` → saída 1 (a efêmera fica no banco). Antes, o script tinha 2 falsos positivos/negativos corrigidos (nome da sala era prefixo dos e-mails; janela dos logs começava tarde)
- [x] Stack derrubada sem `-v`; banco sem dados de teste

Pendente:
- [ ] Lista de membros (e cargo de dono) assinada: sem ela o servidor pode afirmar que um cúmplice é o dono (limite em `docs/06` §4.6)
- [ ] Parte B (frontend núcleo)
- [ ] Parte C (frontend completo, revisão, code-simplifier, verificação final)
