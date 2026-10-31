// Sessão do canal em tempo real (docs/03-protocolo.md) no navegador. O
// cookie de sessão vai sozinho no upgrade (mesma origem); a URL tem de ser
// wss:// no MESMO host da página (B-D3). Eventos para quem usa (onEvent):
//   { type: "status", status: connecting | ready | reconnecting | signed-out | closed }
//   { type: "deliver", packet }  MSG_DELIVER (decifrar é com o cliente E2EE)
//   { type: "room", packet }     ROOM_EVENT
//   { type: "subscribed" | "unsubscribed", room }
//   { type: "error", packet }    ERROR que não é de um envio
// Envios: send() devolve uma promessa resolvida no MSG_ACK ou rejeitada no
// ERROR (ref = cid), no prazo ou no close(). Numa queda, os pendentes são
// reenviados com o MESMO cid depois do WELCOME (o servidor é idempotente).
const PROTOCOL_VERSION = 1;
const BASE_DELAY_MS = 1000;
const MAX_DELAY_MS = 30000;
const RATE_LIMITED_DELAY_MS = 60000;
const SESSION_ENDED = 4401;
const RATE_LIMITED = 4429;

export class SendError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "SendError";
    this.code = code;
  }
}

// Jitter com o aleatório do Web Crypto (nada de Math.random no projeto).
const cryptoRandom = () => globalThis.crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32;

const checkUrl = (url, origin) => {
  const parsed = new URL(url);
  if (parsed.protocol !== "wss:") throw new Error("o WebSocket só é aberto com wss://");
  if (origin && parsed.host !== new URL(origin).host) throw new Error("o WebSocket só é aberto na mesma origem da página");
};

export class WsSession {
  constructor({ url, WebSocketImpl = globalThis.WebSocket, onEvent = () => {}, random = cryptoRandom, ackTimeoutMs = 10000, origin = globalThis.location?.origin }) {
    checkUrl(url, origin);
    Object.assign(this, { url, WebSocketImpl, onEvent, random, ackTimeoutMs });
    this.rooms = new Set();
    this.pending = new Map(); // cid → { packet, resolve, reject, timer }
    this.ready = false;
    this.attempt = 0;
    this.stopped = false;
    this.socket = null;
    this.retryTimer = null;
  }

  status(status) {
    this.onEvent({ type: "status", status });
  }

  connect() {
    this.stopped = false;
    this.status(this.attempt === 0 ? "connecting" : "reconnecting");
    const socket = new this.WebSocketImpl(this.url);
    this.socket = socket;
    socket.onopen = () => this.raw({ type: "HELLO", client: "secure-chat-web" });
    socket.onmessage = (event) => this.receive(event.data);
    socket.onclose = (event) => this.closed(socket, event.code);
    socket.onerror = () => {};
  }

  raw(packet) {
    this.socket?.send(JSON.stringify({ v: PROTOCOL_VERSION, ...packet }));
  }

  receive(data) {
    let packet;
    try {
      packet = JSON.parse(data);
    } catch {
      return; // quadro inválido: ignorado (nunca exibido)
    }
    if (!packet || typeof packet !== "object") return;
    switch (packet.type) {
      case "WELCOME":
        this.ready = true;
        this.attempt = 0;
        this.status("ready");
        for (const room of this.rooms) this.raw({ type: "SUBSCRIBE", id: `sub-${room}`, room });
        for (const { packet: p } of this.pending.values()) this.raw(p);
        return;
      case "MSG_ACK": {
        const entry = this.pending.get(packet.cid);
        if (!entry) return; // ACK de cid que não está pendente não confirma nada
        this.settle(packet.cid);
        entry.resolve({ id: packet.id, ts: packet.ts });
        return;
      }
      case "ERROR": {
        const entry = this.pending.get(packet.ref);
        if (entry) {
          this.settle(packet.ref);
          entry.reject(new SendError(packet.code, packet.message));
          return;
        }
        this.onEvent({ type: "error", packet });
        return;
      }
      case "MSG_DELIVER":
        this.onEvent({ type: "deliver", packet });
        return;
      case "ROOM_EVENT":
        this.onEvent({ type: "room", packet });
        return;
      case "SUBSCRIBED":
      case "UNSUBSCRIBED":
        this.onEvent({ type: packet.type.toLowerCase(), room: packet.room });
        return;
      default:
    }
  }

  closed(socket, code) {
    if (socket !== this.socket) return;
    this.ready = false;
    this.socket = null;
    if (this.stopped) return;
    if (code === SESSION_ENDED) {
      this.stopped = true;
      this.rejectAll("SIGNED_OUT");
      this.status("signed-out");
      return;
    }
    const base = code === RATE_LIMITED ? RATE_LIMITED_DELAY_MS : Math.min(BASE_DELAY_MS * 2 ** this.attempt, MAX_DELAY_MS);
    const delay = base + Math.floor(this.random() * base * 0.5);
    this.attempt += 1;
    this.status("reconnecting");
    this.retryTimer = setTimeout(() => this.connect(), delay);
  }

  subscribe(room) {
    this.rooms.add(room);
    if (this.ready) this.raw({ type: "SUBSCRIBE", id: `sub-${room}`, room });
  }

  unsubscribe(room) {
    this.rooms.delete(room);
    if (this.ready) this.raw({ type: "UNSUBSCRIBE", room });
  }

  send({ room, cid, body }) {
    const packet = { type: "MSG_SEND", id: cid, room, cid, body };
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.settle(cid);
        reject(new SendError("TIMEOUT", "sem confirmação do servidor"));
      }, this.ackTimeoutMs);
      this.pending.set(cid, { packet, resolve, reject, timer });
      if (this.ready) this.raw(packet);
    });
  }

  settle(cid) {
    clearTimeout(this.pending.get(cid)?.timer);
    this.pending.delete(cid);
  }

  rejectAll(code) {
    for (const [cid, entry] of [...this.pending]) {
      this.settle(cid);
      entry.reject(new SendError(code));
    }
  }

  close() {
    this.stopped = true;
    clearTimeout(this.retryTimer);
    this.rejectAll("CLOSED");
    const socket = this.socket;
    this.socket = null;
    this.ready = false;
    socket?.close(1000);
    this.status("closed");
  }
}
