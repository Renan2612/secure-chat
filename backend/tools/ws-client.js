#!/usr/bin/env node
// Cliente de referência do protocolo de tempo real (docs/03-protocolo.md),
// com criptografia ponta a ponta (docs/05-e2ee.md). Faz login por HTTP(S),
// abre o keystore cifrado, abre o WebSocket com o cookie da sessão, HELLO →
// WELCOME, registra as chaves públicas, SUBSCRIBE na sala, obtém a chave da
// sala e então: cada linha digitada é CIFRADA e vira um MSG_SEND; cada
// MSG_DELIVER é decifrado, verificado e impresso como [verificado] ou
// [não verificado]. Fim da entrada (Ctrl+D) encerra a conexão e faz logout.
//
// Uso (a partir de backend/), pela origem única do proxy (Etapa 4a):
//   CHAT_PASSWORD=... CHAT_KEY_PASSPHRASE=... node tools/ws-client.js \
//     --server https://localhost/api --ca ../certs/caddy-local-root.crt \
//     --origin https://localhost --email alice@example.com --create-room "Sala"
//   (o outro lado: --room <id> --join <convite>; depois, só --room <id>)
// Opções: --server (base da API; padrão http://localhost:8000), --ws (URL do
// WebSocket; padrão: /ws na mesma origem do --server, ws:// ou wss://),
// --origin, --ca (certificado de uma CA extra em que confiar, além das do
// sistema; NODE_EXTRA_CA_CERTS também vale), --ack-timeout-ms (padrão 10000),
// --room <id>, --create-room <nome>, --join <convite> (com --room),
// --keystore <arquivo> (padrão ~/.config/secure-chat/<email>.json; nunca
// dentro de um repositório git), --reset-keys (substitui as chaves públicas
// no servidor pelas deste keystore).
// Comandos (linhas que começam com /): /members, /safety <id>, /trust <id>,
// /approve <id>, /keys. O /trust só confirma a chave cujo número de
// segurança o /safety mostrou. A chave da sala só é entregue sozinha a
// membros VERIFICADOS; os demais precisam de /approve (quem decide quem é
// membro é o servidor).
//
// A verificação do certificado NUNCA é desligada (não existe --insecure), e
// com --server https:// o WebSocket só pode ser wss:// (o cookie de sessão
// não sai em claro).
// Sem CHAT_PASSWORD, a senha é pedida no terminal (sem eco); idem a senha de
// cifragem do keystore (CHAT_KEY_PASSPHRASE), que precisa ser DIFERENTE da de
// login (esta vai ao servidor; aquela nunca sai da máquina). Nenhuma das duas
// é aceita como argumento: argumentos ficam visíveis no `ps` e no histórico.
// Envio sem MSG_ACK em --ack-timeout-ms é avisado como não confirmado.
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");
const readline = require("readline");
const tls = require("tls");
const WebSocket = require("ws");
const e2ee = require("../../shared/e2ee");
const { defaultKeystorePath } = require("../../shared/e2ee/node");
const { E2eeSession, clean } = require("./e2ee-session");

const PROTOCOL_VERSION = 1;
// Erros de certificado comuns quando a CA local não está configurada.
const CERT_ERRORS = new Set([
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
]);
const describeError = (err) => {
  const base = err.code ? `${err.message} (${err.code})` : err.message;
  return CERT_ERRORS.has(err.code)
    ? `${base}; para a CA local do Caddy use --ca certs/caddy-local-root.crt (scripts/export-ca.sh)`
    : base;
};
const LOOPBACK = /^(localhost|127(\.\d{1,3}){3}|\[::1\])$/;
const OPTIONS = ["server", "ws", "origin", "email", "room", "ca", "ack-timeout-ms", "keystore", "create-room", "join"];
const FLAGS = ["reset-keys"];

const fail = (message) => {
  process.stderr.write(`erro: ${message}\n`);
  process.exit(1);
};

// O WebSocket fica em /ws na raiz da MESMA origem da API: com o proxy, a API
// é https://host/api e o canal é wss://host/ws.
const wsUrlFor = (server) => {
  const url = new URL("/ws", server);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
};

const parseUrl = (value, schemes, option) => {
  let url;
  try {
    url = new URL(value);
  } catch {
    return fail(`--${option} não é uma URL válida`);
  }
  if (!schemes.includes(url.protocol)) fail(`--${option} deve usar ${schemes.map((s) => `${s}//`).join(" ou ")}`);
  // Sem TLS, a senha (login) e o cookie (WebSocket) iriam em claro: só na
  // própria máquina.
  if ((url.protocol === "http:" || url.protocol === "ws:") && !LOOPBACK.test(url.hostname)) {
    fail(`--${option} ${url.protocol}// só é aceito para localhost (a senha e o cookie iriam em claro); use https:// ou wss://`);
  }
  return url;
};

const parseArgs = (argv) => {
  // O Node desligaria a verificação de certificado de TODO o processo.
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    fail("NODE_TLS_REJECT_UNAUTHORIZED=0 desliga a verificação de certificado; remova-o (use --ca)");
  }
  const args = {
    server: "http://localhost:8000",
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    "ack-timeout-ms": "10000",
  };
  for (let i = 0; i < argv.length; i += 1) {
    const name = argv[i]?.replace(/^--/, "");
    if (FLAGS.includes(name)) {
      args[name] = true;
      continue;
    }
    if (!OPTIONS.includes(name) || argv[i + 1] === undefined) {
      fail(`argumento inválido: ${argv[i]}`);
    }
    args[name] = argv[i + 1];
    i += 1;
  }
  if (!args.email || (!args.room && !args["create-room"])) fail("informe --email e --room (ou --create-room)");
  if (args.room && args["create-room"]) fail("use --room ou --create-room, não os dois");
  if (args.join && !args.room) fail("--join exige --room");
  if (args.room) {
    args.room = Number(args.room);
    if (!Number.isInteger(args.room) || args.room <= 0) fail("--room deve ser um inteiro positivo");
  }
  try {
    args.keystore = args.keystore ?? defaultKeystorePath(args.email);
  } catch (err) {
    fail(err.message);
  }
  args.ackTimeoutMs = Number(args["ack-timeout-ms"]);
  if (!(args.ackTimeoutMs > 0)) fail("--ack-timeout-ms deve ser positivo");

  const server = parseUrl(args.server, ["http:", "https:"], "server");
  args.server = args.server.replace(/\/+$/, "");
  args.ws = parseUrl(args.ws ?? wsUrlFor(args.server), ["ws:", "wss:"], "ws").toString();
  // Sem rebaixamento: se a API é HTTPS, o cookie não pode ir por ws:// em claro.
  if (server.protocol === "https:" && !args.ws.startsWith("wss:")) {
    fail("com --server https:// o WebSocket deve ser wss:// (o cookie de sessão iria em claro)");
  }
  if (args.ca) {
    let pem;
    try {
      pem = fs.readFileSync(args.ca, "utf8");
    } catch (err) {
      return fail(`não foi possível ler --ca (${err.code ?? err.message})`);
    }
    // Explicitar `ca` substitui as CAs padrão do Node: soma às do sistema
    // (e à do NODE_EXTRA_CA_CERTS, se houver) em vez de trocá-las.
    const extra = [];
    if (process.env.NODE_EXTRA_CA_CERTS) {
      try {
        extra.push(fs.readFileSync(process.env.NODE_EXTRA_CA_CERTS, "utf8"));
      } catch (err) {
        return fail(`não foi possível ler NODE_EXTRA_CA_CERTS (${err.code ?? err.message})`);
      }
    }
    args.tlsCa = [...tls.rootCertificates, ...extra, pem];
  }
  return args;
};

// Lê uma senha no terminal sem mostrar o que é digitado.
const askHidden = (label, envName) =>
  new Promise((resolve) => {
    if (!process.stdin.isTTY) fail(`defina ${envName} (sem terminal para perguntar a ${label})`);
    process.stdout.write(`${label}: `);
    const { stdin } = process;
    stdin.setRawMode(true);
    stdin.resume();
    let password = "";
    const onData = (chunk) => {
      for (const ch of chunk.toString("utf8")) {
        if (ch === "\r" || ch === "\n") {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off("data", onData);
          process.stdout.write("\n");
          resolve(password);
          return;
        }
        if (ch === "\u0003") process.exit(130); // Ctrl+C
        password = ch === "\u007f" ? password.slice(0, -1) : password + ch;
      }
    };
    stdin.on("data", onData);
  });

// Requisição HTTP(S) com a CA extra (o fetch do Node não aceita `ca`). Não
// segue redirecionamentos: um 308 de http:// para https:// vira erro, em vez
// de reenviar a senha por conta própria.
const request = (url, { method, headers, body, ca, timeoutMs = 10000 }) =>
  new Promise((resolve, reject) => {
    const target = new URL(url);
    const transport = target.protocol === "https:" ? https : http;
    const req = transport.request(target, { method, headers, ...(ca ? { ca } : {}) }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        data += chunk;
      });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
      // Conexão cortada no meio da resposta: sem isto a promessa nunca
      // terminava e o processo saía 0, calado.
      const incomplete = () => reject(Object.assign(new Error("resposta incompleta do servidor"), { code: "ECONNRESET" }));
      res.on("error", incomplete);
      res.on("close", () => {
        if (!res.complete) incomplete();
      });
    });
    req.setTimeout(timeoutMs, () => req.destroy(Object.assign(new Error("tempo esgotado"), { code: "ETIMEDOUT" })));
    req.on("error", reject);
    req.end(body);
  });

const login = async ({ server, origin, email, tlsCa }, password) => {
  const res = await request(`${server}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: origin },
    body: JSON.stringify({ email, password }),
    ca: tlsCa,
  });
  if (res.status >= 300 && res.status < 400) {
    fail(`login falhou (${res.status}): o cliente não segue redirecionamentos; use --server https://…/api`);
  }
  if (res.status !== 200) fail(`login falhou (${res.status})`);
  const sid = (res.headers["set-cookie"] ?? []).map((c) => c.split(";")[0]).find((c) => c.startsWith("sid="));
  if (!sid) fail("o servidor não devolveu o cookie de sessão");
  return { cookie: sid, body: res.body };
};

// Avisa se o logout falhar: sem ele, o cookie continua valendo até a sessão
// expirar.
const logout = async ({ server, origin, tlsCa }, cookie) => {
  const warn = (why) =>
    process.stderr.write(`aviso: logout falhou (${why}); a sessão pode continuar válida até expirar\n`);
  try {
    const res = await request(`${server}/logout`, {
      method: "POST",
      headers: { Cookie: cookie, Origin: origin },
      ca: tlsCa,
      timeoutMs: 3000,
    });
    if (res.status !== 204) warn(res.status);
  } catch (err) {
    warn(err.code ?? err.message);
  }
};

// TODA linha impressa passa pelo clean (caracteres de controle visíveis):
// ids, nomes, textos e códigos podem vir do servidor ou de outro usuário.
// As quebras de linha das mensagens do próprio cliente são preservadas.
const print = (line) => process.stdout.write(`${String(line).split("\n").map(clean).join("\n")}\n`);

// Requisição JSON autenticada para a sessão E2EE (chaves, salas).
const apiFor = ({ server, origin, tlsCa }, cookie) => async (method, path, body) => {
  const res = await request(`${server}${path}`, {
    method: method.toUpperCase(),
    headers: { Cookie: cookie, Origin: origin, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    ca: tlsCa,
  });
  let parsed = null;
  let parseError = false;
  try {
    parsed = res.body ? JSON.parse(res.body) : null;
  } catch {
    parseError = true; // a sessão transforma isso num erro claro (ok())
  }
  return { status: res.status, body: parsed, parseError };
};

const main = async () => {
  // Se alguma promessa ficar pendente e o processo acabar sozinho, sai com 1.
  process.exitCode = 1;
  const args = parseArgs(process.argv.slice(2));
  const password = process.env.CHAT_PASSWORD || (await askHidden("senha", "CHAT_PASSWORD"));
  const passphrase = process.env.CHAT_KEY_PASSPHRASE || (await askHidden("senha de cifragem do keystore", "CHAT_KEY_PASSPHRASE"));
  if (passphrase === password) fail("a senha de cifragem do keystore deve ser diferente da senha de login");
  const { cookie, body } = await login(args, password);
  let user;
  try {
    user = JSON.parse(body);
  } catch {
    await logout(args, cookie); // a sessão já existe: não largá-la viva
    fail("resposta inválida do login");
  }
  print(`logado como ${clean(user.name)} (usuário ${clean(user.id)})`);

  const session = new E2eeSession({
    api: apiFor(args, cookie),
    me: user,
    email: args.email,
    keystorePath: args.keystore,
    passphrase,
    print,
  });
  try {
    await session.open();
  } catch (err) {
    await logout(args, cookie);
    fail(err.code === "BAD_PASSPHRASE" ? "senha de cifragem errada (ou keystore adulterado); o keystore NÃO foi alterado" : err.message);
  }

  let ws;
  try {
    ws = new WebSocket(args.ws, {
      headers: { Cookie: cookie },
      origin: args.origin,
      ...(args.tlsCa ? { ca: args.tlsCa } : {}),
    });
  } catch (err) {
    await logout(args, cookie); // a sessão já existe: não largá-la viva
    fail(`conexão: ${describeError(err)}`);
  }
  const send = (packet) => ws.send(JSON.stringify({ v: PROTOCOL_VERSION, ...packet }));
  const pending = new Map(); // cid → timer, para envios ainda sem MSG_ACK
  let inputEnded = false;
  let inputStarted = false;
  let room = args.room;
  // Linhas digitadas e eventos tratados EM ORDEM (cifrar é assíncrono).
  let queue = Promise.resolve();
  let queued = 0;

  let exitCode = 0;
  let finishing = false;
  const finish = async (code) => {
    if (finishing) return;
    finishing = true;
    await logout(args, cookie);
    process.exit(code);
  };
  // Erros depois do login também fazem logout antes de sair.
  const abort = (message) => {
    process.stderr.write(`erro: ${message}\n`);
    finish(1);
  };
  const settle = (cid) => {
    clearTimeout(pending.get(cid));
    pending.delete(cid);
  };
  const maybeFinish = () => {
    if (inputEnded && pending.size === 0 && queued === 0) ws.close(1000);
  };
  const enqueue = (task) => {
    queued += 1;
    queue = queue
      .then(task)
      .catch((err) => {
        print(`! erro: ${describeError(err)}`);
        exitCode = 1;
      })
      .finally(() => {
        queued -= 1;
        maybeFinish();
      });
  };

  const sendText = async (line) => {
    if (!session.hasCurrentKey(room)) {
      print("! sem a chave da sala: mensagem NÃO enviada (aguardando um membro entregá-la)");
      exitCode = 1;
      return;
    }
    if (new TextEncoder().encode(line).length > e2ee.MAX_TEXT_BYTES) {
      print(`! mensagem longa demais (máximo ${e2ee.MAX_TEXT_BYTES} bytes): NÃO enviada`);
      exitCode = 1;
      return;
    }
    const cid = crypto.randomUUID();
    const body = await session.encrypt(room, cid, line);
    // Sem ACK no prazo (ex.: descartada pelo rate limit, que não responde
    // a cada quadro), a linha é dada como não enviada.
    pending.set(
      cid,
      setTimeout(() => {
        print(`! sem confirmação: "${line.slice(0, 40)}" (cid ${cid}); reenvie se quiser`);
        exitCode = 1;
        settle(cid);
        maybeFinish();
      }, args.ackTimeoutMs)
    );
    // id = cid: um ERROR sobre este envio volta com ref = cid.
    send({ type: "MSG_SEND", id: cid, room, cid, body });
  };

  const command = async (line) => {
    const [name, arg] = line.trim().split(/\s+/);
    const userId = Number(arg);
    switch (name) {
      case "/keys":
        return print(`suas chaves: fingerprint ${await e2ee.fingerprint(session.pub)}; key_epoch ${session.keyEpoch}; keystore ${args.keystore}`);
      case "/members": {
        const res = await session.api("get", `/roomUsers/${room}`);
        if (res.status !== 200) return print(`! não foi possível listar os membros (${res.status})`);
        print(`membros da sala ${room}:`);
        for (const member of res.body) {
          if (member.id === user.id) {
            print(`  ${member.id} ${clean(member.name)} ${(await e2ee.fingerprint(session.pub)).slice(0, 16)} [você]`);
            continue;
          }
          const status = await session.observe(member.id);
          const fp = session.trust.peers[member.id]?.fingerprint ?? "sem chave pública";
          print(`  ${member.id} ${clean(member.name)} ${status === null ? fp : fp.slice(0, 16)} [${session.trustLabel(member.id)}]`);
        }
        return undefined;
      }
      case "/safety": {
        if (!Number.isInteger(userId) || userId <= 0) return print("uso: /safety <userId>");
        const { number, changed } = await session.safety(userId);
        return print(
          `número de segurança com usuário ${userId}${changed ? " (CHAVE ALTERADA)" : ""}:\n  ${number}\n` +
            `confira com a outra pessoa por um canal seguro (pessoalmente, ligação); se for igual: /trust ${userId}`
        );
      }
      case "/trust": {
        if (!Number.isInteger(userId) || userId <= 0) return print("uso: /trust <userId>");
        try {
          await session.confirm(userId);
        } catch (err) {
          return print(`! ${err.message}`);
        }
        print(`usuário ${userId} marcado como verificado`);
        return session.distribute(room); // pode ter ficado sem chave por causa da mudança
      }
      case "/approve": {
        if (!Number.isInteger(userId) || userId <= 0) return print("uso: /approve <userId>");
        try {
          return await session.approve(room, userId);
        } catch (err) {
          return print(`! ${err.message}`);
        }
      }
      default:
        return print("comandos: /members, /safety <userId>, /trust <userId>, /approve <userId>, /keys");
    }
  };

  const startInput = () => {
    const rl = readline.createInterface({ input: process.stdin });
    rl.on("line", (line) => {
      if (!line) return;
      enqueue(() => (line.startsWith("/") ? command(line) : sendText(line)));
    });
    rl.on("close", () => {
      inputEnded = true;
      maybeFinish();
    });
  };

  // Depois do WELCOME: chaves no diretório, criar ou entrar na sala, e só
  // então SUBSCRIBE.
  const setup = async () => {
    await session.registerKeys({ reset: args["reset-keys"] });
    if (args["create-room"]) {
      const created = await session.createRoom(args["create-room"]);
      room = created.id;
      print(`sala criada: id ${created.id}; convite: ${created.key} (repasse o id e o convite por fora do sistema)`);
    } else if (args.join) {
      const joined = await session.api("post", "/joinRooms", { idRoom: room, key: args.join });
      if (joined.status !== 200) throw new Error(`não foi possível entrar na sala (${joined.status})`);
      print(`entrou na sala ${room}`);
    }
    send({ type: "SUBSCRIBE", id: "subscribe", room });
  };

  const announceKey = async () => {
    const got = await session.ensureRoomKey(room);
    if (got.ok) {
      const from = got.sender === undefined || got.sender === user.id ? "" : `; entregue por usuário ${got.sender} [${session.trustLabel(got.sender)}]`;
      print(`chave da sala ${room} disponível (v${session.currentVersion.get(room)}${from})`);
      await session.distribute(room);
    } else {
      print(`sem a chave da sala ${room}: aguardando um membro entregá-la`);
    }
  };

  const showDelivery = async (packet) => {
    const result = await session.accept(packet);
    const who = `sala ${clean(packet.room)} · usuário ${clean(packet.from)}`;
    switch (result.status) {
      case "ok":
        return print(`[${clean(packet.ts)}] ${who} [${result.verified ? "verificado" : "não verificado"}]: ${clean(result.text)}`);
      case "duplicate":
        return undefined; // reentrega: já foi mostrada
      case "untrusted":
        return print(`! ${who}: mensagem recusada (${result.trust === "changed" ? "CHAVE ALTERADA" : "remetente sem chave conhecida"}); confira /safety ${packet.from} e /trust ${packet.from}`);
      case "missing_key":
        return print(`! ${who}: mensagem com a chave v${result.kv}, que este cliente não tem`);
      default:
        return print(`! ${who}: mensagem inválida descartada (${clean(result.reason ?? "não confere")})`);
    }
  };

  ws.on("unexpected-response", (req, res) => abort(`upgrade recusado (${res.statusCode})`));
  ws.on("error", (err) => abort(`conexão: ${describeError(err)}`));
  ws.on("open", () => send({ type: "HELLO", client: "ws-client.js" }));
  ws.on("close", (code, reason) => {
    print(`conexão encerrada (${code}${reason.length ? ` ${clean(reason)}` : ""})`);
    // Pendentes podem ter sido gravados ou não: reenviar com o mesmo cid
    // seria seguro (idempotente), mas este cliente não guarda os cids.
    if (pending.size > 0) {
      print(`! sem confirmação: ${pending.size} mensagem(ns) enviada(s) sem MSG_ACK`);
      for (const cid of [...pending.keys()]) settle(cid);
      exitCode = 1;
    }
    finish(code === 1000 ? exitCode : 1);
  });

  ws.on("message", (data) => {
    let packet;
    try {
      packet = JSON.parse(data.toString("utf8"));
    } catch {
      packet = null;
    }
    if (!packet || typeof packet !== "object") return print("! quadro inválido recebido do servidor");
    switch (packet.type) {
      case "WELCOME":
        print(`protocolo v${clean(packet.v)}; limites: ${clean(JSON.stringify(packet.limits))}`);
        return setup().catch((err) => {
          print(`! ${err.message}`);
          exitCode = 1;
          ws.close(1000);
        });
      case "SUBSCRIBED":
        if (inputStarted) return undefined; // um segundo SUBSCRIBED não abre outra leitura da entrada
        inputStarted = true;
        print(`inscrito na sala ${clean(packet.room)}. Digite mensagens (Ctrl+D para sair; /members, /safety, /trust, /approve, /keys).`);
        enqueue(announceKey);
        return startInput();
      case "ROOM_EVENT":
        if (packet.room !== room) return undefined;
        if (packet.kind === "KEY_PENDING") return enqueue(() => session.distribute(room));
        if (packet.kind === "KEY_READY") return enqueue(announceKey);
        return undefined;
      case "MSG_ACK":
        // ACK de cid que não está pendente (expirado ou desconhecido) não
        // vira "enviada".
        if (!pending.has(packet.cid)) return undefined;
        settle(packet.cid);
        print(`✓ enviada (id ${packet.id})`);
        return maybeFinish();
      case "MSG_DELIVER":
        return enqueue(() => showDelivery(packet));
      case "ERROR":
        print(`! ${clean(packet.code)}: ${clean(packet.message)}`);
        if (packet.ref === "subscribe") {
          exitCode = 1; // sem a inscrição não há o que fazer
          return ws.close(1000);
        }
        if (pending.has(packet.ref)) {
          settle(packet.ref);
          exitCode = 1;
        }
        return maybeFinish();
      default:
        return undefined;
    }
  });
};

if (require.main === module) {
  main().catch((err) => fail(describeError(err)));
}

module.exports = { wsUrlFor };
