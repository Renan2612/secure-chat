# Etapa 5 (Partes B e C) — Frontend com E2EE

Cliente web do secure-chat: React 19 + Vite 8, em JavaScript, servido pelo
Caddy na origem única `https://localhost`. A criptografia é a MESMA do
backend e do `ws-client`: `shared/e2ee`, sem cópia nem alteração, pelo alias
`@e2ee` do Vite. Plano: [`plano-etapa5.md`](plano-etapa5.md); formatos:
[`05-e2ee.md`](05-e2ee.md); privacidade: [`06-privacidade.md`](06-privacidade.md).

## 1. Como abrir

```bash
docker compose --env-file backend/.env up --build -d   # também builda o frontend
scripts/export-ca.sh certs/caddy-local-root.crt        # certificado da CA local (sem a chave)
```

Importe `certs/caddy-local-root.crt` no navegador como autoridade de
certificação confiável **só para identificar sites** (Firefox: Configurações
→ Privacidade e Segurança → Certificados → Ver certificados → Autoridades →
Importar; Chrome/Chromium: Configurações → Privacidade e segurança →
Segurança → Gerenciar certificados → Autoridades). Depois abra
`https://localhost`. Sem a CA, o navegador recusa o certificado — o
esperado.

## 2. Arquitetura

| Parte | Arquivo | Papel |
|---|---|---|
| núcleo | `shared/e2ee` (alias `@e2ee`) | toda a criptografia e as verificações: envelope v2, wraps, compromisso, TOFU, número de segurança, nome assinado (`openRoomName`) |
| adaptador | `src/crypto/browser.js` | o equivalente do `shared/e2ee/node.js`: privadas importadas como **não extraíveis** |
| cofre | `src/crypto/vault.js`, `idb.js` | identidade, estado das salas e trust store selados no IndexedDB |
| cliente | `src/chat/client.js` | as regras do `ws-client` sobre o cofre: chave da sala, entrega, rotação, nome, mensagens |
| tempo real | `src/chat/wsSession.js` | `/ws`: HELLO/WELCOME, inscrições, ACK com prazo, reconexão com backoff e reenvio pelo mesmo `cid` |
| mensagens | `src/chat/messages.js` | redutor puro: deduplicação por (remetente, `cid`), estados, expiração |
| telas | `src/ui/*.jsx`, `src/strings.js`, `src/styles.css` | textos em PT-BR num arquivo; CSS puro com os tokens do design |

Sem roteador (hash `#/sala/<id>`), sem biblioteca de estado nem de UI.
Dependências de produção: só `react` e `react-dom`, em versões exatas.

## 3. Onde ficam as chaves

- **Cofre** (IndexedDB `secure-chat`, um registro por parte): `identity`
  (ECDH + ECDSA), `state` (chaves de sala recebidas, criador e versão
  fixados, último nome verificado com o maior `seq`, removidos) e `trust`
  (trust store). Cada um no **formato do `keystore.js`** (PBKDF2-SHA-256 com
  ≥ 600 000 iterações + AES-256-GCM, cabeçalho no AAD), sob a **senha de
  cifragem**, distinta da senha de login. `state` e `trust` levam o id do
  cofre: um registro de outro cofre é recusado.
- **Em memória**, com o cofre aberto: as privadas como `CryptoKey` **não
  extraíveis** (o PKCS#8 só existe durante a criação e o desbloqueio); as
  chaves de sala como `CryptoKey` extraíveis (é preciso embrulhá-las para os
  novos membros); a senha de cifragem (para selar de novo a cada mudança).
- **Nunca**: `localStorage`, `sessionStorage`, cookies legíveis ou disco
  fora do IndexedDB selado. Texto decifrado só na memória da aba.
- **Bloqueio**: 15 min sem interação, o botão "Bloquear" e o logout fecham o
  `/ws` e apagam chaves e mensagens da memória.
- **Sem recuperação**: perdeu a senha de cifragem ou os dados do navegador,
  perdeu as chaves. A tela de criação exige marcar "Entendi".

## 4. CSP e entrega pelo proxy

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'self' wss://localhost; base-uri 'none';
form-action 'self'; frame-ancestors 'none'; object-src 'none'
```

Mais `nosniff`, `Referrer-Policy: no-referrer`, COOP `same-origin` e
`Permissions-Policy` restritiva. O build não gera nada inline (nenhum
`<script>` sem `src`, nenhum `style=`); `index.html` sem cache, `/assets/*`
com hash no nome e `immutable`. O `dist` é publicado por um serviço de build
(multi-estágio, `npm ci`) num volume que o Caddy monta **somente leitura**.

## 5. Render seguro

Mensagens, nomes de sala e nomes de exibição são sempre nós de **texto** do
React (escapados): nada de `innerHTML`, `dangerouslySetInnerHTML`, autolink
ou markdown (o `verify-frontend.sh` falha se aparecerem no `src/`). Mensagem
que não confere vira o marcador "mensagem inválida", sem conteúdo. O nome
de exibição é escolhido pelo próprio usuário: aparece sempre com o id
(`Alice · #3`); quem é quem de verdade é o selo de verificação.

## 6. Testes

| O quê | Como | Arquivo |
|---|---|---|
| paridade com OpenSSL/Python e com o Node | `npm test` (vitest) | `tests/parity.test.js` |
| cofre (formato, senha, adulteração, outro cofre, memória) | `npm test` | `tests/vault.test.js` |
| cliente, membros, rotação, nome (servidor adversário) | `npm test` | `tests/client.test.js`, `tests/members.test.js` |
| `/ws` e redutor | `npm test` | `tests/wsSession.test.js`, `tests/messages.test.js` |
| ponta a ponta com **Chromium real** contra a stack | `npm run e2e` | `e2e/chat.spec.js` |
| build, dist, src, dependências, CSP servida (+ 4 mutações) | `scripts/verify-frontend.sh` | — |

O ponta a ponta (C5) usa o Chromium headless de `~/.cache/ms-playwright`
(`npx playwright install chromium`, **sem** `--with-deps` e sem sudo). O
certificado não é ignorado: o Chromium aceita só a SPKI do intermediário da
CA local, depois de o OpenSSL conferir que ele é assinado pela raiz
exportada. Os usuários `e2e-*@example.invalid` são apagados na saída.

## 7. Limites honestos

1. **O código vem do servidor.** Quem controla o servidor (ou o Caddy)
   pode servir um JavaScript que lê as mensagens decifradas ou a senha de
   cifragem. A E2EE no navegador protege contra o banco, os logs e a rede
   interna — não contra o operador que troca o código. Mitigações reais
   (extensão que fixa o código, app instalado, *code transparency*) estão
   fora do escopo.
2. **XSS ou extensão maliciosa = E2EE comprometida.** Com o cofre aberto, um
   script na página USA as chaves não extraíveis (não precisa lê-las). A CSP
   e o render só em texto reduzem a chance de XSS; extensões do navegador
   ficam fora do alcance da página.
3. **Rollback do cofre.** Quem consegue escrever no IndexedDB deste perfil
   (malware local, acesso ao disco) pode repor uma cópia ANTIGA dos três
   registros **juntos**, todos válidos e da mesma senha: o cofre abre sem
   aviso e volta, por exemplo, a um trust store de antes de um contato ser
   fixado (o TOFU fixaria de novo o que o servidor mandar) ou a um `seq` do
   nome menor. Detectar isso exigiria um contador fora do navegador. O
   mesmo vale para o keystore do Node ([`05-e2ee.md`](05-e2ee.md) §12.3).
4. **Senha de cifragem igual à de login.** A comparação só é possível na
   **mesma carga de página** do login (a senha de login fica na memória só
   até o cofre existir). Se a página foi recarregada depois do login (sessão
   retomada pelo `GET /me`), a tela de criação mostra um aviso claro e não
   consegue conferir. Igual à de login, a senha de cifragem estaria nas mãos
   do servidor, que recebe a de login.
5. **Sem recuperação de chaves** (§3).
6. **Memória do navegador**: chaves e textos decifrados existem na memória
   da aba enquanto o cofre está aberto; um dump de memória ou o swap podem
   guardá-los. O bloqueio por inatividade encurta essa janela.
7. **Captura de tela e cópia**: a expiração tira a mensagem da tela e da
   memória deste cliente; não desfaz o que alguém fotografou, copiou ou
   guardou com um cliente modificado.
8. **Metadados**: o servidor ainda vê quem fala com quem, quando (minuto) e
   o tamanho (em blocos) — [`06-privacidade.md`](06-privacidade.md) §3.
