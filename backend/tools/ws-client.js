#!/usr/bin/env node
// Cliente de referência do protocolo de tempo real (docs/03-protocolo.md).
// Faz login por HTTP, abre o WebSocket em /ws com o cookie da sessão,
// HELLO → WELCOME, SUBSCRIBE na sala e então: cada linha digitada vira um
// MSG_SEND; cada MSG_DELIVER recebido é impresso. Fim da entrada (Ctrl+D)
// encerra a conexão e faz logout.
//
// Uso (a partir de backend/):
//   CHAT_PASSWORD=... node tools/ws-client.js --email alice@example.com --room 1 \
//     [--server http://localhost:8000] [--origin http://localhost:3000]
// Sem CHAT_PASSWORD, a senha é pedida no terminal (sem eco). Envio sem
// MSG_ACK em --ack-timeout-ms (padrão 10000) é avisado como não confirmado. Ela nunca é
// aceita como argumento: argumentos ficam visíveis no `ps` e no histórico.
//
// Útil para a demonstração e para as capturas no Wireshark (hoje sem TLS:
// todo o tráfego, inclusive o body, aparece em claro).
const crypto = require("crypto");
const readline = require("readline");
const WebSocket = require("ws");

const PROTOCOL_VERSION = 1;

const fail = (message) => {
  process.stderr.write(`erro: ${message}\n`);
  process.exit(1);
};

const parseArgs = (argv) => {
  const args = {
    server: "http://localhost:8000",
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    "ack-timeout-ms": "10000",
  };
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i]?.replace(/^--/, "");
    if (!["server", "origin", "email", "room", "ack-timeout-ms"].includes(name) || argv[i + 1] === undefined) {
      fail(`argumento inválido: ${argv[i]}`);
    }
    args[name] = argv[i + 1];
  }
  if (!args.email || !args.room) fail("informe --email e --room");
  args.room = Number(args.room);
  if (!Number.isInteger(args.room) || args.room <= 0) fail("--room deve ser um inteiro positivo");
  args.ackTimeoutMs = Number(args["ack-timeout-ms"]);
  if (!(args.ackTimeoutMs > 0)) fail("--ack-timeout-ms deve ser positivo");
  return args;
};

// Lê a senha no terminal sem mostrar o que é digitado.
const askPassword = () =>
  new Promise((resolve) => {
    if (!process.stdin.isTTY) fail("defina CHAT_PASSWORD (sem terminal para perguntar a senha)");
    process.stdout.write("senha: ");
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

const login = async ({ server, origin, email }, password) => {
  const res = await fetch(`${server}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: origin },
    body: JSON.stringify({ email, password }),
  });
  if (res.status !== 200) fail(`login falhou (${res.status})`);
  const setCookies = res.headers.getSetCookie?.() ?? [res.headers.get("set-cookie") ?? ""];
  const sid = setCookies.map((c) => c.split(";")[0]).find((c) => c.startsWith("sid="));
  if (!sid) fail("o servidor não devolveu o cookie de sessão");
  const user = await res.json();
  return { cookie: sid, user };
};

// Avisa se o logout falhar: sem ele, o cookie (que, sem TLS, passou em claro
// pela rede) continua valendo até a sessão expirar.
const logout = async ({ server, origin }, cookie) => {
  const warn = (why) =>
    process.stderr.write(`aviso: logout falhou (${why}); a sessão pode continuar válida até expirar\n`);
  try {
    const res = await fetch(`${server}/logout`, {
      method: "POST",
      headers: { Cookie: cookie, Origin: origin },
      signal: AbortSignal.timeout(3000),
    });
    if (res.status !== 204) warn(res.status);
  } catch (err) {
    warn(err.cause?.code ?? err.message);
  }
};

const print = (line) => process.stdout.write(`${line}\n`);

const main = async () => {
  const args = parseArgs(process.argv.slice(2));
  const password = process.env.CHAT_PASSWORD || (await askPassword());
  const { cookie, user } = await login(args, password);
  print(`logado como ${user.name} (usuário ${user.id})`);

  const wsUrl = `${args.server.replace(/^http/, "ws")}/ws`;
  const ws = new WebSocket(wsUrl, { headers: { Cookie: cookie }, origin: args.origin });
  const send = (packet) => ws.send(JSON.stringify({ v: PROTOCOL_VERSION, ...packet }));
  const pending = new Map(); // cid → timer, para envios ainda sem MSG_ACK
  let inputEnded = false;

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
    if (inputEnded && pending.size === 0) ws.close(1000);
  };

  const startInput = () => {
    const rl = readline.createInterface({ input: process.stdin });
    rl.on("line", (line) => {
      if (!line) return;
      const cid = crypto.randomUUID();
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
      send({ type: "MSG_SEND", id: cid, room: args.room, cid, body: line });
    });
    rl.on("close", () => {
      inputEnded = true;
      maybeFinish();
    });
  };

  ws.on("unexpected-response", (req, res) => abort(`upgrade recusado (${res.statusCode})`));
  ws.on("error", (err) => abort(`conexão: ${err.message}`));
  ws.on("open", () => send({ type: "HELLO", client: "ws-client.js" }));
  ws.on("close", (code, reason) => {
    print(`conexão encerrada (${code}${reason.length ? ` ${reason}` : ""})`);
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
        print(`protocolo v${packet.v}; limites: ${JSON.stringify(packet.limits)}`);
        return send({ type: "SUBSCRIBE", id: "subscribe", room: args.room });
      case "SUBSCRIBED":
        print(`inscrito na sala ${packet.room}. Digite mensagens (Ctrl+D para sair).`);
        return startInput();
      case "MSG_ACK":
        settle(packet.cid);
        print(`✓ enviada (id ${packet.id})`);
        return maybeFinish();
      case "MSG_DELIVER":
        return print(`[${packet.ts}] sala ${packet.room} · usuário ${packet.from}: ${packet.body}`);
      case "ERROR":
        print(`! ${packet.code}: ${packet.message}`);
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

main().catch((err) => fail(err.cause?.code ? `${err.message} (${err.cause.code})` : err.message));
