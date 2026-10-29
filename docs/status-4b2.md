# Status da Etapa 4b-2 (temporário)

Fonte para retomar o trabalho depois de limite de uso ou queda. No item 7,
este conteúdo vai para o `docs/05-e2ee.md` e este arquivo é removido.

| Item | Estado |
|---|---|
| 1. Migração (owner_id, rotation_required, invite_hash, room_bans) | feito |
| 2. Sair, transferir e remover | pendente |
| 3. Rotação no servidor | pendente |
| 4. Cliente: rotação, comandos, rotação automática, eventos | pendente |
| 5. P1, P2 e P3 | pendente |
| 6. verify-e2ee.sh com três usuários | pendente |
| 7. Documentação | pendente |

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
