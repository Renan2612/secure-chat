// Sessão do /ws no navegador (B4): HELLO → WELCOME, SUBSCRIBE (refeito a
// cada reconexão), MSG_SEND com MSG_ACK ou ERROR (ref = cid) e prazo,
// reconexão com backoff exponencial e jitter, reenvio com o MESMO cid
// (idempotente no servidor), e o que NÃO reconecta (logout 4401, close nosso).
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { WsSession } from "../src/chat/wsSession.js";

class FakeSocket {
  static all = [];
  constructor(url) {
    this.url = url;
    this.sent = [];
    this.readyState = 0;
    FakeSocket.all.push(this);
  }
  send(data) {
    this.sent.push(JSON.parse(data));
  }
  close(code = 1000) {
    this.readyState = 3;
    this.onclose?.({ code });
  }
  // lado do "servidor"
  open() {
    this.readyState = 1;
    this.onopen?.();
  }
  push(packet) {
    this.onmessage?.({ data: JSON.stringify({ v: 1, ...packet }) });
  }
  drop(code = 1006) {
    this.readyState = 3;
    this.onclose?.({ code });
  }
}

const last = () => FakeSocket.all.at(-1);
const ready = (socket = last()) => {
  socket.open();
  socket.push({ type: "WELCOME", limits: {} });
};

let session;
let events;

beforeEach(() => {
  vi.useFakeTimers();
  FakeSocket.all = [];
  events = [];
  session = new WsSession({
    url: "wss://chat.example/ws",
    WebSocketImpl: FakeSocket,
    random: () => 0, // jitter mínimo: atrasos determinísticos
    onEvent: (e) => events.push(e),
    ackTimeoutMs: 5000,
  });
  session.connect();
});
afterEach(() => {
  session.close();
  vi.useRealTimers();
});

describe("handshake e inscrições", () => {
  test("HELLO ao abrir; WELCOME → pronto; SUBSCRIBE das salas pedidas", () => {
    session.subscribe(7);
    last().open();
    expect(last().sent).toEqual([{ v: 1, type: "HELLO", client: "secure-chat-web" }]);
    last().push({ type: "WELCOME", limits: {} });
    expect(last().sent.slice(1)).toEqual([{ v: 1, type: "SUBSCRIBE", id: "sub-7", room: 7 }]);
    expect(events).toContainEqual({ type: "status", status: "ready" });
  });

  test("só wss na mesma origem: URL ws:// ou de outro host é recusada", () => {
    expect(() => new WsSession({ url: "ws://chat.example/ws", WebSocketImpl: FakeSocket })).toThrow();
    expect(() => new WsSession({ url: "wss://outro.example/ws", WebSocketImpl: FakeSocket, origin: "https://chat.example" })).toThrow();
  });

  test("MSG_DELIVER e ROOM_EVENT chegam como eventos; quadro inválido é ignorado", () => {
    ready();
    last().onmessage({ data: "não é json" });
    last().push({ type: "MSG_DELIVER", room: 7, id: 1, from: 2, cid: "c", ts: "t", body: "{}" });
    last().push({ type: "ROOM_EVENT", room: 7, kind: "KEY_READY" });
    expect(events.filter((e) => e.type === "deliver")).toHaveLength(1);
    expect(events).toContainEqual({ type: "room", packet: { v: 1, type: "ROOM_EVENT", room: 7, kind: "KEY_READY" } });
  });
});

describe("envio", () => {
  test("MSG_SEND → MSG_ACK resolve com id e ts", async () => {
    ready();
    const sent = session.send({ room: 7, cid: "c1", body: "env" });
    expect(last().sent.at(-1)).toEqual({ v: 1, type: "MSG_SEND", id: "c1", room: 7, cid: "c1", body: "env" });
    last().push({ type: "MSG_ACK", cid: "c1", id: 42, ts: "2026-10-31T10:00:00.000Z" });
    await expect(sent).resolves.toEqual({ id: 42, ts: "2026-10-31T10:00:00.000Z" });
  });

  test("ERROR com ref = cid rejeita com o código", async () => {
    ready();
    const sent = session.send({ room: 7, cid: "c1", body: "env" });
    last().push({ type: "ERROR", ref: "c1", code: "ROTATION_PENDING", message: "x" });
    await expect(sent).rejects.toMatchObject({ code: "ROTATION_PENDING" });
  });

  test("sem ACK no prazo → falhou (TIMEOUT)", async () => {
    ready();
    const sent = session.send({ room: 7, cid: "c1", body: "env" });
    vi.advanceTimersByTime(5001);
    await expect(sent).rejects.toMatchObject({ code: "TIMEOUT" });
  });

  test("ACK de cid desconhecido não confirma nada", () => {
    ready();
    expect(() => last().push({ type: "MSG_ACK", cid: "nunca-enviado", id: 1, ts: "t" })).not.toThrow();
  });
});

describe("reconexão", () => {
  test("queda (1006): reconecta com backoff 1 s, 2 s, 4 s…; refaz SUBSCRIBE e reenvia o pendente com o MESMO cid", async () => {
    session.subscribe(7);
    ready();
    const sent = session.send({ room: 7, cid: "c1", body: "env" });
    last().drop();
    expect(events).toContainEqual({ type: "status", status: "reconnecting" });
    expect(FakeSocket.all).toHaveLength(1);
    vi.advanceTimersByTime(1000);
    expect(FakeSocket.all).toHaveLength(2);
    last().drop(); // falhou de novo
    vi.advanceTimersByTime(1999);
    expect(FakeSocket.all).toHaveLength(2);
    vi.advanceTimersByTime(1);
    expect(FakeSocket.all).toHaveLength(3);
    ready();
    const types = last().sent.map((p) => p.type);
    expect(types).toEqual(["HELLO", "SUBSCRIBE", "MSG_SEND"]);
    expect(last().sent[2]).toMatchObject({ cid: "c1", body: "env" });
    last().push({ type: "MSG_ACK", cid: "c1", id: 5, ts: "t" });
    await expect(sent).resolves.toEqual({ id: 5, ts: "t" });
  });

  test("o atraso tem teto de 30 s e volta a 1 s depois de um WELCOME", () => {
    for (let i = 0; i < 8; i += 1) {
      last().drop();
      vi.advanceTimersByTime(30000);
    }
    const before = FakeSocket.all.length;
    last().drop();
    vi.advanceTimersByTime(29999);
    expect(FakeSocket.all).toHaveLength(before);
    vi.advanceTimersByTime(1);
    ready();
    last().drop();
    vi.advanceTimersByTime(1000);
    expect(FakeSocket.all).toHaveLength(before + 2);
  });

  test("4401 (sessão encerrada): NÃO reconecta e avisa signed-out", () => {
    ready();
    last().drop(4401);
    vi.advanceTimersByTime(60000);
    expect(FakeSocket.all).toHaveLength(1);
    expect(events).toContainEqual({ type: "status", status: "signed-out" });
  });

  test("4429 (ritmo): espera 60 s antes de tentar de novo", () => {
    ready();
    last().drop(4429);
    vi.advanceTimersByTime(59999);
    expect(FakeSocket.all).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(FakeSocket.all).toHaveLength(2);
  });

  test("close() nosso: não reconecta e rejeita os pendentes", async () => {
    ready();
    const sent = session.send({ room: 7, cid: "c1", body: "env" });
    session.close();
    vi.advanceTimersByTime(60000);
    expect(FakeSocket.all).toHaveLength(1);
    await expect(sent).rejects.toMatchObject({ code: "CLOSED" });
  });
});
