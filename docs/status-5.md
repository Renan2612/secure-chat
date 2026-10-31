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

## Parte B — frontend núcleo

Feito:
- [x] `GET /me` (id e nome) atrás do requireAuth, com testes; SameSite=Lax corrigido nos comentários e no docs/06
- [x] B1 projeto React 19.3.1 + Vite 8.3.5 em `frontend/`, versões exatas, `npm ci`, lockfile só com registry.npmjs.org, 0 vulnerabilidades em produção
- [x] B1 `shared/e2ee` reutilizado sem alteração (alias `@e2ee`); adaptador de navegador (`src/crypto/browser.js`); paridade com os vetores OpenSSL/Python e com vetores produzidos pelo Node
- [x] B1 cofre selado no IndexedDB, formato do keystore.js (PBKDF2 ≥ 600 000 + AES-GCM), senha de cifragem distinta da de login, privadas não extraíveis, lock apaga a memória, sem recuperação (avisado)
- [x] Achados da revisão automática no cofre e no cliente: state amarrado ao id do cofre (conferido antes de mesclar); gravações em série sobre o último estado; ensureRoomKey simultâneo compartilhado
- [x] Cliente E2EE do navegador (`src/chat/client.js`): as regras do ws-client sobre o núcleo; nome só com a assinatura do dono atual (openRoomName) e maior seq no cofre
- [x] B2 telas de login/cadastro e de criar/desbloquear o cofre; logout por POST
- [x] B3 salas: lista com nome decifrado ou "Sala #id (nome não verificado)", criar com o limite de 100 bytes mostrado ao digitar, convite mostrado uma vez com copiar, entrar com ID e convite, "aguardando chave"
- [x] B4 sessão WS (HELLO/WELCOME, SUBSCRIBE refeito na reconexão, ACK com prazo, backoff 1–30 s com jitter, reenvio com o mesmo cid, 4401 sem reconexão), histórico paginado, deduplicação, estados (enviando, confirmada, falhou, inválida, sem chave), expiração; tudo em memória; texto sempre como texto
- [x] B5 Caddy serve o dist de um volume somente leitura, CSP do plano, index sem cache, assets imutáveis; build multi-estágio no compose; página provisória removida
- [x] B5 `scripts/verify-tls.sh` atualizado e executado: saída 0. Corrigido no caminho: cadastro, login e prova do rate limit sem `Origin` (quebrados desde o CSRF da Parte A)
- [x] Suíte completa: backend 765 passaram, 1 pulado; frontend 61 passaram
- [x] Stack derrubada sem `-v`; banco sem dados de teste

Itens da Parte B resolvidos na Parte C: navegador real (C5), URLs no bundle (C4), senha igual à de login (aviso, docs/07), rollback do cofre (docs/07).

## Parte C — frontend completo

Feito:
- [x] C1 cliente: número de segurança (12 × 5) e confirmação só da chave exibida; entrega automática só a verificados, aprovação explícita para os demais, CHAVE ALTERADA e removidos nunca; rotação com chave nova e o mesmo nome assinado (ou null); remover, sair, transferir, convite, banimentos, renomear, re-assinatura do novo dono
- [x] C1–C3 interface: painel de membros e ajustes, bloqueio visível de CHAVE ALTERADA, rotação automática no ROTATION_PENDING, sala travada, removido, reconectando; C2 seletor de expiração limitado pela retenção e contagem regressiva; C3 gaveta no celular (390 px), Esc, foco visível, aria-live, textos PT-BR num arquivo
- [x] Acréscimo (b): senha de cifragem igual à de login recusada na mesma carga de página; depois de recarregar, aviso claro (limite em docs/07 §7)
- [x] C4 `scripts/verify-frontend.sh` (o que o navegador busca, tolerando textos de URL; nada inline; src sem HTML montado; versões fixas; lockfile; audit; CSP servida) e 4 mutações que saem com 1 (inline-script, external-script, inner-html, unpinned-dep)
- [x] C5 vitest (cofre, paridade, cliente, membros, /ws, redutor) e ponta a ponta com Chromium real (Playwright, ~/.cache, sem sudo) contra a stack; achou e corrigiu o nome da sala que não aparecia ao receber a chave
- [x] C6 docs/07-frontend.md e atualizações em 00, 01, 03, 05, 06 e README

Pendente:
- [ ] C7 fechamento: review-pr (tests errors) e code-simplifier uma vez; npm test e audit nos dois; up --build; verify-tls, verify-e2ee, verify-frontend; stack derrubada; banco limpo
