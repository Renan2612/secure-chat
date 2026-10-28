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
// Sem CHAT_PASSWORD, a senha é pedida no terminal (sem eco). Ela nunca é
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
  const args = { server: "http://localhost:8000", origin: process.env.CLIENT_URL || "http://localhost:3000" };
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i]?.replace(/^--/, "");
    if (!["server", "origin", "email", "room"].includes(name) || argv[i + 1] === undefined) {
      fail(`argumento inválido: ${argv[i]}`);
    }
    args[name] = argv[i + 1];
  }
  if (!args.email || !args.room) fail("informe --email e --room");
  args.room = Number(args.room);
  if (!Number.isInteger(args.room) || args.room <= 0) fail("--room deve ser um inteiro positivo");
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

const logout = ({ server, origin }, cookie) =>
  fetch(`${server}/logout`, { method: "POST", headers: { Cookie: cookie, Origin: origin } }).catch(() => {});

const print = (line) => process.stdout.write(`${line}\n`);

const main = async () => {
  const args = parseArgs(process.argv.slice(2));
  const password = process.env.CHAT_PASSWORD || (await askPassword());
  const { cookie, user } = await login(args, password);
  print(`logado como ${user.name} (usuário ${user.id})`);

  const wsUrl = `${args.server.replace(/^http/, "ws")}/ws`;
  const ws = new WebSocket(wsUrl, { headers: { Cookie: cookie }, origin: args.origin });
  const send = (packet) => ws.send(JSON.stringify({ v: PROTOCOL_VERSION, ...packet }));
  const pending = new Set(); // cids enviados ainda sem MSG_ACK
  let inputEnded = false;

  let exitCode = 0;
  const finish = async (code) => {
    await logout(args, cookie);
    process.exit(code);
  };
  const maybeFinish = () => {
    if (inputEnded && pending.size === 0) ws.close(1000);
  };

  const startInput = () => {
    const rl = readline.createInterface({ input: process.stdin });
    rl.on("line", (line) => {
      if (!line) return;
      const cid = crypto.randomUUID();
      pending.add(cid);
      // id = cid: um ERROR sobre este envio volta com ref = cid.
      send({ type: "MSG_SEND", id: cid, room: args.room, cid, body: line });
    });
    rl.on("close", () => {
      inputEnded = true;
      maybeFinish();
    });
  };

  ws.on("unexpected-response", (req, res) => fail(`upgrade recusado (${res.statusCode})`));
  ws.on("error", (err) => fail(`conexão: ${err.message}`));
  ws.on("open", () => send({ type: "HELLO", client: "ws-client.js" }));
  ws.on("close", (code, reason) => {
    print(`conexão encerrada (${code}${reason.length ? ` ${reason}` : ""})`);
    finish(code === 1000 ? exitCode : 1);
  });

  ws.on("message", (data) => {
    let packet;
    try {
      packet = JSON.parse(data.toString("utf8"));
    } catch {
      return print("! quadro inválido recebido do servidor");
    }
    switch (packet.type) {
      case "WELCOME":
        print(`protocolo v${packet.v}; limites: ${JSON.stringify(packet.limits)}`);
        return send({ type: "SUBSCRIBE", id: "subscribe", room: args.room });
      case "SUBSCRIBED":
        print(`inscrito na sala ${packet.room}. Digite mensagens (Ctrl+D para sair).`);
        return startInput();
      case "MSG_ACK":
        pending.delete(packet.cid);
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
        pending.delete(packet.ref);
        return maybeFinish();
      default:
        return undefined;
    }
  });
};

main().catch((err) => fail(err.message));
