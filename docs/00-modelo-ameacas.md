# Etapa 0 — Modelo de Ameaças

> Projeto da disciplina de Redes — Engenharia de Software
> Base: fork saneado de [asafebxd/MessageWebApp](https://github.com/asafebxd/MessageWebApp)

## 1. Objetivo do sistema

Um chat em tempo real (texto, em salas e mensagens diretas) com o objetivo de
ser **seguro e privado por padrão**: o servidor não deve conseguir ler o
conteúdo das conversas, e a rede não deve expor nada em trânsito.

## 2. Escopo

**Dentro do escopo:**
- Autenticação de usuários.
- Mensagens de texto em salas (grupos).
- Mensagens diretas (1 para 1).
- Criptografia ponta a ponta do conteúdo das mensagens.
- TLS em todo o tráfego cliente-servidor.
- Infraestrutura própria (Docker, proxy reverso, firewall).

**Fora do escopo (a menos que sobre tempo):**
- Chamadas de voz e vídeo.
- Compartilhamento de arquivos grandes.
- Múltiplos dispositivos por usuário (sincronização de chaves entre
  dispositivos é um problema complexo por si só — ver Signal/MLS).
- Federação entre servidores.

## 3. Atores

| Ator | Descrição |
|---|---|
| **Usuário legítimo** | Tem conta no sistema, participa de salas e DMs normalmente. |
| **Atacante externo (rede)** | Não tem conta. Está na mesma rede (Wi-Fi público, ISP, Wi-Fi do campus) ou em algum ponto entre cliente e servidor. Consegue capturar pacotes (sniffing), mas não tem credenciais. |
| **Outro usuário autenticado (malicioso)** | Tem conta válida no sistema. Tenta acessar salas ou mensagens que não são dele, ou se passar por outro usuário. |
| **Administrador do servidor** | Controla a máquina onde o backend e o banco rodam. Pode ler qualquer coisa que o servidor processe em texto claro, incluindo logs e banco de dados. Este é o ator mais importante do projeto, porque é o que justifica a criptografia ponta a ponta. |
| **Atacante com acesso ao banco** | Obteve uma cópia do banco de dados (vazamento, backup mal protegido, SQL injection). Sobrepõe-se parcialmente com o admin, mas vale tratar separado porque pode não ter acesso ao servidor em execução. |

## 4. O que estamos protegendo

| Ativo | Contra quem | Como |
|---|---|---|
| **Conteúdo das mensagens** | Rede, admin do servidor, acesso ao banco | Criptografia ponta a ponta (E2EE): o servidor só manipula texto cifrado. |
| **Credenciais (senha)** | Rede, admin do servidor | TLS em trânsito; hash com `bcrypt` em repouso (já existe no projeto base). |
| **Identidade do remetente** | Outro usuário malicioso | O servidor define o remetente pela sessão autenticada, nunca pelo que o cliente informa no corpo da requisição. |
| **Metadados (quem fala com quem, quando)** | Parcialmente — ver limitação abaixo | Minimizar logs, reduzir o que fica em claro nas tabelas. |
| **Pertencimento às salas** | Outro usuário malicioso | Toda rota de leitura/escrita verifica se o usuário é membro da sala (Etapa 2). |

### Situação na Etapa 5 (privacidade e frontend)

A [Etapa 5](06-privacidade.md) acrescenta mensagens efêmeras com expiração
assinada, retenção por sala, o nome da sala cifrado e assinado pelo dono,
CSRF e redução de metadados; o [frontend](07-frontend.md) leva a E2EE ao
navegador (cofre selado no IndexedDB, chaves privadas não extraíveis, CSP
restritiva). **Ator novo no modelo:** o código do cliente web vem do
servidor — um servidor malicioso pode servir JavaScript que lê o que o
usuário decifra; XSS e extensões do navegador também comprometem a E2EE
enquanto o cofre está aberto ([`07-frontend.md`](07-frontend.md) §7).

### Situação na Etapa 4b-1 (E2EE, núcleo)

Com a [Etapa 4b-1](05-e2ee.md), estes ativos passam a estar protegidos
também contra o **administrador do servidor** e contra quem tem **acesso ao
banco**, e não só contra a rede:

| Ativo | Agora protegido por | Prova |
|---|---|---|
| **Conteúdo das mensagens** | AES-256-GCM no cliente com a chave da sala; o servidor guarda só o envelope `{v,kv,iv,ct,sig}` | `scripts/verify-e2ee.sh` (banco e rede interna proxy → backend), `tests/ws/e2eeMessages.test.js` |
| **Chave da sala** (ativo novo) | gerada no cliente; só existe embrulhada (ECDH + HKDF + AES-GCM) para a chave pública de cada membro | `tests/roomKeys.test.js` |
| **Chaves privadas dos usuários** (ativo novo) | nunca saem do cliente; keystore cifrado (PBKDF2 600 000 + AES-GCM), 0600, fora de repositórios | `tests/e2ee/keystore.test.js` |
| **Identidade do remetente** | além do `from` definido pela sessão, assinatura ECDSA verificada com a chave **fixada** do remetente: nem o servidor consegue forjar autoria | `tests/ws/e2eeMessages.test.js` ("servidor troca o `from`") |

**Continua fora:** metadados, disponibilidade (o servidor pode omitir ou
reordenar), a primeira troca de chaves sem conferir o número de segurança,
o dispositivo do usuário e a senha de login (que chega ao servidor). Lista
completa em [`05-e2ee.md`](05-e2ee.md) §10.

### Limitação honesta sobre metadados

Mesmo com E2EE, o servidor — e portanto o admin — sempre vai saber **quem
está conversando com quem, quando e com que frequência**, porque ele precisa
rotear as mensagens para o destinatário certo. Isso é uma limitação de
qualquer arquitetura cliente-servidor (inclusive do WhatsApp e do Signal).
Reduzir isso de verdade exigiria roteamento anônimo (tipo Tor), que está fora
do escopo deste projeto. Vamos deixar isso explícito no relatório final, em
vez de prometer algo que não entregamos.

## 5. Fora do modelo de ameaças (não vamos nos proteger disso)

- **Dispositivo do usuário comprometido** (malware, tela desbloqueada). Se o
  atacante já controla o endpoint, nenhuma criptografia de rede ajuda.
- **Ataques de engenharia social** (phishing de senha).
- **Negação de serviço (DDoS) em larga escala.** Vamos ter rate limiting
  básico, mas não é o foco da disciplina.
- **Comprometimento do navegador** (extensões maliciosas lendo a Web Crypto
  API antes da cifragem).

## 6. Casos de ataque que vamos demonstrar (Etapa 6)

1. **Sniffing de rede**: capturar o tráfego no Wireshark na versão original
   (HTTP puro) e mostrar o texto da mensagem em claro; repetir na versão
   final (TLS + E2EE) e mostrar que não dá para ler nada.
2. **Se passar por outro usuário**: tentar forjar o remetente de uma
   mensagem ou a sessão de outro usuário; mostrar que a versão saneada
   rejeita.
3. **Ler sala alheia (IDOR)**: tentar acessar `/messages/:id` de uma sala
   da qual o usuário não é membro; mostrar que a versão com autorização
   (Etapa 2) bloqueia.
4. **Admin do servidor lendo o banco**: mostrar o conteúdo da tabela
   `messages` antes (texto claro) e depois (ciphertext) da Etapa 4.

## 7. O que precisa ser autoral (combinar com o professor)

Pontos a confirmar com o professor antes de seguir:
- [ ] Partir de um projeto de terceiros como base é aceitável, desde que
      documentado e com atribuição?
- [ ] O protocolo de comunicação (Etapa 3) precisa ser implementado do zero
      sobre TCP/WebSocket, ou o Socket.IO corrigido é aceitável?
- [ ] A implementação de E2EE precisa ser escrita do zero, ou pode usar
      bibliotecas estabelecidas (Web Crypto API nativa é aceitável; uma lib
      pronta tipo libsodium.js também deve ser, mas convém confirmar)?
