# Etapa 6 — andamento

Plano: [`plano-etapa6.md`](plano-etapa6.md). Para retomar: ler este arquivo e o plano.

## Parte A — comparação antes e depois

Feito:
- [x] Clone do original fixado no SHA `873df2cd…` em `.cache/` (gitignored); `.gitignore` cobre `.cache/` e `evidencias/`; SHA e ajustes de boot em `docs/09`
- [x] A1 `scripts/compare/run-original.sh` + `original.compose.yml` + `original.Dockerfile` + `stop-original.sh`: sobe API (127.0.0.1:18000) e Postgres (sem porta) do original, projeto próprio, trap de limpeza com `down -v` só do projeto do original
- [x] A2 cliente de ataque em `attacks/` (package próprio, versões exatas, só `socket.io-client` e `ws`, `npm ci`, 0 vulnerabilidades, lockfile só npmjs)
- [x] A3 `attack-matrix.sh` roda os 11 ataques contra original (vulnerável) e final (bloqueado), com asserção por alvo, controle positivo e saída 1 se alguma defesa da FINAL falhar; `render-matrix.js` grava `matriz.{md,json}`
- [x] Trava de alvo local (`lib-local-guard.sh`, também em `matrix.js`): aborta se o alvo não for 127.0.0.1/localhost
- [x] A4 capturas comparativas: `evidencias/etapa6/sniff-original.pcapng` (28 pacotes, senha+mensagem em claro) e `sniff-final-externo.pcapng` (63 pacotes, senha ausente), não commitadas
- [x] A5 mutações: (i) `MUTATION=skip-defense` desliga a autorização por sala (flag `TEST_SKIP_ROOM_MEMBER`, nunca ativa por padrão) → matriz sai com 1 (#3 quebrada); (ii) `MUTATION=nonlocal-target` → trava aborta com saída 3
- [x] Matriz final: 13/13 defesas da versão final confirmadas; original vulnerável em todos os itens aplicáveis. Saída 0
- [x] Stack do original derrubada; banco final sem usuários de teste

Resultado da matriz (resumo): todos os ataques que funcionam no original
(sniffing, falsificar identidade, ler sala alheia, ouvinte anônimo, vazamento
de hash, entrar sem convite, banco em claro, CSRF, CSWSH, força bruta, flags
de cookie, HSTS/CSP, TLS) são **bloqueados** na stack final.

Decisões tomadas sozinho (registradas):
- Imagem efêmera do original (não vendorizada) em vez de montar o clone
  gravável — mantém o `.cache` intacto e evita compilar deps nativas.
- A matriz recria o backend da final antes dos ataques, para zerar o rate
  limit em memória entre reexecuções (o plano já prevê "429: reinicie o backend").
- Item 7 (banco) na FINAL é checado pelo schema (CHECK de envelope, `name_env`);
  os dados vivos cifrados já são provados por `verify-e2ee.sh`.
- Item 8b (CSWSH) no original é reportado conforme observado: o `socket.io`
  aplica o CORS dele no handshake.

Pendente:
- [ ] Parte B (endurecimento, perfil de produção, deploy/, CI, verify-hardening)
- [ ] Parte C (docs 08/09, atualizar 00/01/README, fechamento com review + simplifier)
