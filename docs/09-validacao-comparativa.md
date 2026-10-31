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

## Metodologia

`scripts/compare/attack-matrix.sh` sobe as DUAS stacks (original e final),
roda o MESMO conjunto de 11 ataques contra cada uma e grava
`evidencias/etapa6/matriz.{md,json}` (não commitadas). Cada ataque declara,
por alvo, o que se **espera** (`vulneravel` no original, `bloqueado` na
final) e um **controle positivo** (prova de que o ataque funcionaria se a
defesa não existisse). O script sai com **1** se qualquer defesa da versão
**final** for provada quebrada; itens `inconclusivo` (limite de ambiente) e
"original não vulnerável" são reportados com honestidade, sem derrubar a
matriz nem forçar resultado.

- Parte HTTP/WebSocket (itens 2–10, 11h): cliente de ataque em `attacks/`
  (`socket.io-client` para o socket do original, `ws` para o `/ws` da final).
- Banco (7): leitura direta via `psql` nos dois bancos.
- TLS (11t): `openssl s_client`.
- Escuta de rede (1): `dumpcap` no loopback (sem sudo, grupo wireshark).

**Trava de segurança:** só mira `127.0.0.1`/`localhost`
(`scripts/compare/lib-local-guard.sh`, repetida em `attacks/matrix.js`); um
alvo não-local aborta antes de qualquer ataque (mutação `nonlocal-target`,
saída 3).

## Matriz "antes e depois"

Saída real de `scripts/compare/attack-matrix.sh` (✓ = observado bate com o
esperado): a versão final bloqueia **os 13** itens que funcionam no original.

| # | Ataque | Original (esp./obs.) | Final (esp./obs.) | Controle positivo |
|---|---|---|---|---|
| 1 | Escuta de rede (sniffing) | vulneravel/vulneravel ✓ | bloqueado/bloqueado ✓ | a senha NÃO aparece mesmo com pacotes capturados: o TLS cifra na borda |
| 2 | Falsificar identidade (sessão/remetente) | vulneravel/vulneravel ✓ | bloqueado/bloqueado ✓ | `/session` e `POST /messages` removidos; remetente do MSG_SEND vem da sessão |
| 3 | Ler sala alheia sem ser membro | vulneravel/vulneravel ✓ | bloqueado/bloqueado ✓ | o dono (membro) lê a própria sala (200) |
| 4 | Ouvinte anônimo no WebSocket | vulneravel/vulneravel ✓ | bloqueado/bloqueado ✓ | com sessão o upgrade abre (open=true) |
| 5 | Vazamento do hash de senha | vulneravel/vulneravel ✓ | bloqueado/bloqueado ✓ | `checkUserExists` removido (404) |
| 6 | Entrar em sala sem a chave de convite | vulneravel/vulneravel ✓ | bloqueado/bloqueado ✓ | convite inválido → 403 genérico |
| 7 | Banco legível (texto claro) | vulneravel/vulneravel ✓ | bloqueado/bloqueado ✓ | schema força envelope (CHECK) e nome cifrado; dados vivos em `verify-e2ee.sh` |
| 8a | CSRF (POST com Origin de outro site) | vulneravel/vulneravel ✓ | bloqueado/bloqueado ✓ | com o Origin certo o login responde 200 |
| 8b | CSWSH (WebSocket com Origin de outro site) | vulneravel/vulneravel ✓ | bloqueado/bloqueado ✓ | o upgrade confere o Origin antes da sessão |
| 9 | Força bruta de login | vulneravel/vulneravel ✓ | bloqueado/bloqueado ✓ | a final responde 429 (limitador) |
| 10 | Flags do cookie de sessão | vulneravel/vulneravel ✓ | bloqueado/bloqueado ✓ | `sid` com Secure, HttpOnly e SameSite |
| 11h | Cabeçalhos HSTS e CSP | vulneravel/vulneravel ✓ | bloqueado/bloqueado ✓ | a origem serve HSTS e CSP |
| 11t | TLS e versões | vulneravel/vulneravel ✓ | bloqueado/bloqueado ✓ | TLS 1.2/1.3 aceitos; 1.1 recusado |

### Observações honestas sobre a matriz

- **Mutação (i) sobe o backend em `NODE_ENV=test` (acréscimo b).** Para a
  mutação `skip-defense` desligar a autorização por sala, o backend precisa
  honrar a flag `TEST_SKIP_ROOM_MEMBER`, que só vale em `NODE_ENV=test`
  (docs/08; `backend/config/testFlags.js`). Nesse modo, o cookie de sessão
  perde o atributo `Secure` (`secure: isProduction()`), então a mutação pode
  marcar como quebrado tanto o item 3 (alvo) quanto o 10 (cookie). Isso é
  esperado no cenário de teste e **não afeta a produção**: lá `NODE_ENV=production`
  recusa subir com qualquer flag de teste, e o `sid` sai com `Secure`.
- **CSWSH no original (8b) é PARCIALMENTE protegido pelo CORS do Socket.IO
  (acréscimo b).** O handshake do `socket.io` aplica o CORS configurado
  (`origin` = `urlclient`), então uma conexão com `Origin` de outro site
  explícito às vezes é recusada no handshake. O original continua vulnerável
  ao ouvinte **anônimo** (sem `Origin`, item 4); o 8b é reportado conforme
  observado em cada execução, sem forçar.
- **Item 7 na final** é verificado pelo schema (CHECK de envelope v2,
  coluna `name_env` cifrada); os dados vivos cifrados no banco e na rede
  interna já são provados por `verify-e2ee.sh`.

## Capturas comparativas (A4)

`scripts/compare/attack-matrix.sh` grava em `evidencias/etapa6/`
(não commitadas):

- `sniff-original.pcapng`: tráfego cliente→`127.0.0.1:18000` do original.
  O detector (`scripts/lib/find-plaintext.js`) acha **em claro** tanto a
  senha de login quanto o marcador de mensagem (bytes crus e base64).
- `sniff-final-externo.pcapng`: tráfego na `443` da final. Com dezenas de
  pacotes capturados, a senha **não aparece** (o TLS cifra na borda) — é a
  prova da ausência (0 pacotes seria falso positivo, por isso o script exige
  que a captura tenha tráfego).
- Internamente (proxy→backend, já provado em `verify-e2ee.sh`): a senha de
  login trafega em claro (o TLS termina no proxy — **limite documentado**),
  mas a mensagem vai só como envelope cifrado.

## Limitações honestas

- **O servidor afirma quem é o dono.** `ownerId` vem do servidor; um
  servidor malicioso pode apontar um cúmplice como dono. Fechar isso exige a
  lista de membros assinada (pendente; docs/06 §4.6).
- **Metadados visíveis ao servidor:** quem fala com quem, em que sala, o
  minuto e o tamanho (em blocos) das mensagens (docs/06 §3).
- **O TLS termina no proxy:** entre o proxy e o backend (rede interna do
  Docker) a senha de login trafega em claro; a mensagem, não (é envelope).
- **Um dispositivo por usuário:** o cofre de chaves vive num navegador; não
  há sincronização entre dispositivos.
- **Sem recuperação de chaves:** perder a senha de cifragem ou os dados do
  navegador perde o acesso às conversas (docs/07 §7).
- **O código do frontend vem do servidor:** um servidor malicioso pode
  servir um JavaScript que lê o que o usuário decifra; XSS/extensões também
  comprometem a E2EE com o cofre aberto (docs/07 §7).
- **Backups e páginas antigas do Postgres** retêm o envelope cifrado até o
  `VACUUM`/expiração dos backups (docs/06 §4).
- **Relógio do cliente:** a expiração das mensagens depende do relógio de
  quem envia e de quem lê (tolerância de 5 min; docs/05 §12.1).
- **Firewall e WireGuard (`deploy/`) nunca foram aplicados (acréscimo d):**
  são modelos para o operador aplicar com sudo num host real; não há prova
  de runtime deles nesta entrega (docs/08 §4 e §7).
- **O original bloqueou alguns ataques por conta própria** (ex.: o CORS do
  Socket.IO no 8b): reportado como observado, sem forçar "vulnerável".
