// Utilitários dos testes do protocolo em tempo real (/ws): sobe o servidor
// HTTP de verdade numa porta livre e oferece um cliente WebSocket que
// registra tudo o que recebe, para os testes esperarem por tipos de pacote.
const request = require("supertest");
const WebSocket = require("ws");
const { createServer } = require("../../createServer");
const { PASSWORD } = require("../helpers");

const ORIGIN = "http://localhost:3000"; // = CLIENT_URL em tests/env.js

let counter = 0;

const startServer = async (realtimeOptions = {}) => {
  const instance = createServer({
    appOptions: { authRateLimitMax: 10000, loginEmailRateLimitMax: 10000 },
    realtimeOptions,
  });
  await new Promise((resolve) => instance.server.listen(0, "127.0.0.1", resolve));
  const { port } = instance.server.address();
  return {
    ...instance,
    http: request(instance.server),
    wsUrl: `ws://127.0.0.1:${port}/ws`,
    stop: async () => {
      instance.realtime.close();
      await new Promise((resolve) => instance.server.close(resolve));
    },
  };
};

// Cadastra e loga um usuário; devolve o cookie de sessão ("sid=...").
const loginUser = async (srv, name = "user") => {
  counter += 1;
  const email = `${name}${counter}@ws.example.com`;
  const reg = await srv.http.post("/register").send({ email, password: PASSWORD, name });
  const login = await srv.http.post("/login").send({ email, password: PASSWORD });
  if (login.status !== 200) throw new Error(`login falhou: ${login.status}`);
  const cookie = login.headers["set-cookie"].find((c) => c.startsWith("sid=")).split(";")[0];
  return { id: reg.body.id, email, cookie };
};

// Tenta o upgrade. Resolve com { ws } se abriu, ou { status, body } se o
// servidor recusou o handshake HTTP.
const openSocket = (srv, { cookie, origin = ORIGIN, path = "/ws", ...options } = {}) =>
  new Promise((resolve, reject) => {
    const headers = cookie ? { Cookie: cookie } : {};
    const url = srv.wsUrl.replace(/\/ws$/, path);
    const ws = new WebSocket(url, { headers, ...(origin ? { origin } : {}), ...options });
    const inbox = track(ws);
    ws.once("open", () => resolve({ ws, inbox }));
    ws.once("unexpected-response", (req, res) => {
      let body = "";
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    ws.once("error", (err) => {
      if (ws.readyState !== WebSocket.OPEN) reject(err);
    });
  });

// Guarda os pacotes recebidos e o fechamento, para consulta pelos testes.
const track = (ws) => {
  const inbox = { packets: [], consumed: new Set(), waiters: [], closed: null };
  const settle = () => {
    inbox.waiters = inbox.waiters.filter((w) => !w.check());
  };
  ws.on("message", (data, isBinary) => {
    inbox.packets.push(isBinary ? { binary: data } : JSON.parse(data.toString()));
    settle();
  });
  ws.on("close", (code, reason) => {
    inbox.closed = { code, reason: reason.toString() };
    settle();
  });
  ws.on("error", () => {});
  return inbox;
};

const waitFor = (inbox, predicate, label, timeoutMs = 2000) =>
  new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout esperando ${label}`)), timeoutMs);
    const check = () => {
      const found = predicate(inbox);
      if (found === undefined || found === null || found === false) return false;
      clearTimeout(timer);
      resolve(found);
      return true;
    };
    if (!check()) inbox.waiters.push({ check });
  });

// Próximo pacote do tipo pedido que ainda não foi consumido.
const nextPacket = (inbox, type, timeoutMs) =>
  waitFor(
    inbox,
    (i) => {
      const index = i.packets.findIndex((p, n) => p.type === type && !i.consumed.has(n));
      if (index === -1) return null;
      i.consumed.add(index);
      return i.packets[index];
    },
    type,
    timeoutMs
  );

const closed = (inbox, timeoutMs) => waitFor(inbox, (i) => i.closed, "close", timeoutMs);

const send = (ws, packet) => ws.send(JSON.stringify({ v: 1, ...packet }));

// Abre o socket e faz o handshake de aplicação (HELLO → WELCOME).
const connect = async (srv, cookie, options) => {
  const opened = await openSocket(srv, { cookie, ...options });
  if (!opened.ws) throw new Error(`upgrade recusado: ${opened.status}`);
  send(opened.ws, { type: "HELLO", client: "jest" });
  const welcome = await nextPacket(opened.inbox, "WELCOME");
  return { ...opened, welcome };
};

// Garante que nenhum pacote do tipo chegou dentro da janela.
const expectNoPacket = async (inbox, type, windowMs = 300) => {
  await new Promise((r) => setTimeout(r, windowMs));
  expect(inbox.packets.filter((p, n) => p.type === type && !inbox.consumed.has(n))).toEqual([]);
};

module.exports = {
  ORIGIN,
  startServer,
  loginUser,
  openSocket,
  connect,
  nextPacket,
  closed,
  send,
  expectNoPacket,
};
