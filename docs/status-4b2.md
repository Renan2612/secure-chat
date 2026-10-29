# Status da Etapa 4b-2 (temporário)

Fonte para retomar o trabalho depois de limite de uso ou queda. No item 7,
este conteúdo vai para o `docs/05-e2ee.md` e este arquivo é removido.

| Item | Estado |
|---|---|
| 1. Migração (owner_id, rotation_required, invite_hash, room_bans) | feito |
| 2. Sair, transferir e remover | feito |
| 3. Rotação no servidor | feito (suíte completa: 593 passaram, 1 pulado, o e2e opt-in) |
| 4. Cliente: `/kick`, `/leave`, `/rotate`, `/owner`, `/invite`, rotação automática com atraso de 0 a 2 s, só destinatários verificados, eventos na tela, testes criptográficos | feito |
| 5. P1: trust store ausente com keystore existente → aviso e TOFU reiniciado (id do trust store no keystore) | feito |
| 5. P2: gravação atômica (temporário no mesmo diretório, fsync do arquivo e do diretório, rename, 0600) + teste de falha | feito |
| 5. P3: vetores fixos de fingerprint e número de segurança por ferramenta independente | feito (suíte completa: 632 passaram, 1 pulado) |
| 6. `verify-e2ee.sh` com três usuários (remover, rotacionar, provas a/b/c, mutações sem rotação exigida e com chave antiga reutilizada) | pendente |
| 7. Documentação: docs/05, docs/03, docs/01, README; incorporar este arquivo ao docs/05 e removê-lo | pendente |

## Notas para a documentação (item 7)

- Migração: `migrations.sql` recria o schema. O banco de desenvolvimento
  estava vazio, então basta recriar o volume (`down -v`, que também apaga a
  CA local do Caddy: rode `scripts/export-ca.sh` de novo).
- `rooms.key` (convite em claro) virou `invite_hash` (SHA-256 em hex), e a
  comparação é `timingSafeEqual` entre hashes.
- FKs para `rooms` com `ON DELETE CASCADE`: apagar a sala leva mensagens,
  versões, wraps, vínculos e banimentos.
- "Dono é membro" é garantido pela aplicação, não pelo banco (uma FK
  composta adiada quebraria limpezas diretas no banco feitas pelos testes e
  pelos scripts).
- Rotas novas: `POST /rooms/:id/leave` (200 `{room, roomDeleted}`; 409
  `{code: "OWNER_MUST_TRANSFER"}`), `DELETE /rooms/:id/members/:userId` (200
  `{room, userId, invite}`), `POST /rooms/:id/owner {userId}` (200; 409 se o
  alvo não tem a chave atual). Sala inexistente, sala alheia e alvo que não é
  membro: o mesmo 404 `Sala ou membro inexistente`; membro que não é dono: 403;
  remover a si ou transferir para si: 400.
- `ROOM_EVENT` novos: `REMOVED` (para todas as conexões de quem saiu ou foi
  removido, que é desinscrito sem fechar a conexão) e `ROTATION_PENDING` (para
  os inscritos que ficaram).
- Escolha mais segura: sair também desinscreve e avisa com `REMOVED`; o
  `joinRooms` agora roda numa transação com `FOR SHARE` na sala (banido,
  convite errado e sala inexistente: o mesmo 403).
- Rotação: `POST /rooms/:id/keys/rotate {version, commitment, commitmentSig,
  wraps: [{recipientId, recipientKeyEpoch, wrap}]}` → 201 `{room, version}`.
  403 para não-membro, sala inexistente ou membro sem a chave atual; 409 para
  versão ≠ atual + 1 e para a rotação concorrente que perder; 409
  `{code: "STALE_MEMBERSHIP", members: [{userId, keyEpoch}]}` para destinatário
  que não é membro atual, banido ou com `key_epoch` antigo; 400 para autor fora
  dos wraps, destinatário repetido ou assinatura inválida.
- Escolha mais segura: o servidor também confere as assinaturas do
  compromisso e de cada wrap com a chave pública registrada do autor
  (`helpers/signatures.js`, mesmos rótulos do `shared/e2ee`). Os clientes
  conferem de novo com a chave fixada.
- Corpo da rotação com limite próprio de 100 KB (até 200 wraps), lido só
  depois do `requireAuth`; as outras rotas seguem com 10 KB.
- `MSG_SEND` com `rotation_required` → `ERROR ROTATION_PENDING` (nada
  gravado). Ordem: envelope → `NOT_MEMBER` → `cid` → `ROTATION_PENDING` →
  `KEY_VERSION_MISMATCH`. O INSERT lê a sala com `FOR SHARE` e reavalia a
  condição depois de uma remoção concorrente.
- Escolha mais segura (achado da revisão automática): `POST
  /rooms/:id/keys/wraps` recusa com 409 `ROTATION_PENDING` enquanto a rotação
  é exigida. Quem entra depois de uma saída recebe só a chave nova.
- `ROOM_EVENT KEY_ROTATED` aos inscritos; `KEY_READY` a cada destinatário;
  `KEY_PENDING` se algum membro ficou sem wrap na versão nova.
- `POST /rooms/:id/invite/rotate` (só o dono) → 200 `{room, invite}`, uma
  única vez; membro não dono: 403; não-membro: 404.
- Decisão e limite: quem entra depois de uma rotação recebe só a versão
  atual, então o histórico anterior fica ilegível para ele. Os wraps antigos
  de quem ficou são mantidos.
- Não implementado (registrar em docs/05 como pendência e limite): lista de
  membros assinada pelo dono; histórico de chaves públicas antigas no trust
  store.
- Cliente (item 4, `tools/e2ee-session.js`): `ensureRoomKey` abre TODAS as
  versões que ainda não tem (histórico legível depois da rotação). O
  compromisso da v1 é conferido com o criador fixado; o das versões seguintes,
  com a chave fixada de quem rotacionou. Wrap de versão antiga que não confere:
  aviso, sem descarte (o descarte do servidor só vale para a versão atual).
- Escolha mais segura: o cliente recusa uma versão nova cuja chave repete a
  de outra versão (`KEY_REUSED`), o que pega um membro ou cliente com bug que
  reaproveite a chave que o removido ainda tem.
- Destinatários da rotação: só o próprio usuário e quem está verificado, ou
  quem foi aprovado com `/approve` nesta sessão e nesta sala (a aprovação vive
  só na memória). Os demais ficam pendentes e a saída lista quem ficou de fora.
- Rotação automática: no `ROTATION_PENDING`, quem tem a chave atual espera de
  0 a 2 s (de `getRandomValues`). Se a versão subiu nesse meio-tempo, não
  rotaciona. `STALE_MEMBERSHIP`: refaz até 3 vezes. 409 de versão: busca a
  chave de quem venceu e para.
- Mensagem com kv maior que o conhecido: o cliente busca o wrap e tenta de
  novo; sem wrap, mostra `[sem chave]`.
- `/leave` do dono com outros membros: erro claro, pedindo `/owner`. O
  `REMOVED` da própria saída não é mostrado como remoção.
- Acréscimos (a), (b) e (c): testes em `ws/rotation.test.js` (sala sem ninguém
  com a chave atual: rotação 403, envio `ROTATION_PENDING`, o último a sair
  apaga a sala; mais de 200 wraps → 400; corpo > 100 KB → 413; outras rotas
  seguem com 10 KB) e em `ws/members.test.js` (os dois últimos saem juntos;
  transferir e remover o mesmo membro juntos; dono sai enquanto transfere: o
  dono é sempre membro). Sair, remover, transferir, trocar o convite e
  rotacionar travam a sala com `FOR UPDATE` (`lockRoomFor`, `rotateRoomKey`).
- Achados da revisão automática de segurança (corrigidos depois do item 4):
  (1) a partir da v2, o autor da rotação precisa ser o próprio usuário,
  alguém VERIFICADO ou alguém aprovado com `/approve` nesta sala. Um autor só
  fixado por TOFU não basta: senão, o servidor inseriria uma conta,
  "rotacionaria" com uma chave dele e leria o que viesse depois. Limite: quem
  entra depois de uma rotação precisa verificar quem rotacionou para receber a
  chave (na v1, o criador fixado por TOFU continua aceito, como na 4b-1).
  Depois do `/trust`, o cliente tenta a chave de novo. (2) quem foi removido
  com `/kick` sai do conjunto de aprovados e nunca entra numa rotação daquela
  sessão, mesmo se o servidor voltar a listá-lo.
- P1: `trustStoreId` (16 bytes aleatórios) no keystore e `id` no trust store.
  Trust store ausente → aviso e TOFU reiniciado, com identificador novo. `id`
  diferente → recusa abrir, sem sobrescrever. Keystores da 4b-1 (sem `id`)
  são migrados sem aviso. Ordem das gravações escolhida para que uma falha no
  meio nunca deixe um trust store "aceito" sem aviso.
- P2: `writeSealedFile` grava `.<nome>.tmp-<uuid>` no mesmo diretório, faz
  `fchmod 0600`, escreve, faz `fsync`, `rename` e `fsync` do diretório. Uma
  falha antes do rename apaga o temporário e deixa o arquivo antigo; uma falha
  no `fsync` do diretório é informada (o arquivo novo já está no lugar).
- P3: `tests/e2ee/vectors.test.js`, com chaves do OpenSSL, valores calculados
  em Python (`hashlib`) e a receita de reprodução no próprio teste.
