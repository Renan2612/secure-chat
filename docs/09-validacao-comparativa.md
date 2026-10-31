# Etapa 6 — Validação comparativa "antes e depois"

Compara o projeto **original** (`asafebxd/MessageWebApp`, propositalmente
vulnerável) com a **stack final** deste repositório, rodando o MESMO conjunto
de ataques contra os dois. A metodologia, a matriz completa, as capturas e as
limitações honestas são detalhadas na Parte C desta etapa; este documento é
preenchido ao longo da Etapa 6.

## O original (alvo "antes")

- Repositório: `https://github.com/asafebxd/MessageWebApp`
- Commit fixado (HEAD de `main` em 2026-10-31): **`873df2cd6c4749c0ebf9187079090b9cd84cd541`**
- Não é vendorizado nem commitado (licença ISC; atribuição no README). É
  clonado em `.cache/MessageWebApp` (no `.gitignore`) no SHA acima por
  `scripts/compare/run-original.sh`.
- Isolamento (regra de segurança da etapa): só a API é publicada, e apenas em
  **`127.0.0.1:18000`** (porta diferente das da stack final); o banco não
  publica porta; projeto Docker próprio (`secure-chat-original`) para que a
  limpeza (`down -v`) nunca toque nos volumes da stack final. O original é
  **sempre derrubado** ao fim da matriz (trap).

### Ajustes necessários para subir o original (sem alterar o código dele)

O código do original não foi modificado. O que ele precisa para subir foi
fornecido **só por ambiente/infra**, e está registrado aqui:

| Ajuste | Como | Por quê |
|---|---|---|
| Variáveis de ambiente | `scripts/compare/original.compose.yml` define `serverport`, `urlclient`, `key1` e `DB_*` (nomes escolhidos pelo próprio original; note que `DB_NAME` é usado por ele como o **usuário** do Postgres) | o original lê `process.env` com esses nomes; nada no código foi tocado |
| Imagem efêmera | `scripts/compare/original.Dockerfile` copia o clone e roda `npm install` das deps antigas numa camada em cache (Node 16, para casar com `engines` e com os binários prontos do `bcrypt` 5.1.0) | evita compilar nativo e não "suja" o `.cache`; a imagem é local, nunca enviada |
| Esquema | o próprio `database/migrations.sql` do original é aplicado via `psql` (ele faz `CREATE DATABASE messagewebapp` + `\c`); `DB_DATABASE=messagewebapp` casa com isso | aplica o schema original tal como está |
| Banco em `tmpfs` | `db-orig` usa `tmpfs` para os dados | descartável: some quando o contêiner para |

### Divergências entre este plano/texto e o código do original (vale o código)

- Várias rotas do original **não respondem** (ex.: `POST /register` chama
  `res.status(200)` sem `.send()` → a conexão fica aberta). Todo cliente de
  ataque usa timeout curto em cada requisição por causa disso.
- O `POST /login` só responde no caminho de sucesso; senha errada cai num
  `else` vazio (sem resposta). Por isso a "força bruta" é medida por
  "nenhum 429 em 30 tentativas", não pelo corpo das respostas.
- O `socket.io` do original aplica o CORS dele no handshake: uma conexão com
  `Origin` de outro site explícito às vezes é recusada (o ataque CSWSH é
  reportado conforme observado, sem forçar).

## Matriz, capturas e limitações

A matriz é gerada por `scripts/compare/attack-matrix.sh` em
`evidencias/etapa6/matriz.{md,json}` (não commitadas). A tabela consolidada,
as capturas comparadas e as limitações honestas entram neste documento na
Parte C.
