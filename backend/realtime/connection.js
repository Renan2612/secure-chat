// Uma conexão WebSocket autenticada e sua máquina de estados:
//   AWAITING_HELLO ──HELLO (v ok)──▶ READY
//        │  prazo esgotado → close 4408; versão errada → close 4426;
//        └─ outro pacote → ERROR HELLO_REQUIRED + close 1008
//
// Nunca registra em log o conteúdo dos quadros (o "body" das mensagens vai
// ser cifrado na Etapa 4 e o servidor não deve nem olhar para ele).
const WebSocket = require("ws");
const { PROTOCOL_VERSION, CLOSE, ERRORS, clientPacket } = require("./protocol");

class Connection {
  constructor(socket, { userId, sid, limits, handlers, onRateLimited = () => {} }) {
    this.socket = socket;
    this.userId = userId;
    this.sid = sid;
    this.limits = limits;
    this.handlers = handlers; // { TIPO: async (conn, packet) => void }
    this.onRateLimited = onRateLimited; // chamado no close 4429
    this.ready = false;
    this.rooms = new Set(); // salas em que esta conexão está inscrita
    this.invalidPackets = 0;
    this.tokens = limits.rateBurst;
    this.lastRefill = Date.now();
    this.rateViolations = 0;

    this.helloTimer = setTimeout(() => this.close(CLOSE.HELLO_TIMEOUT, "HELLO não recebido"), limits.helloTimeoutMs);
    socket.on("message", (data, isBinary) => this.onFrame(data, isBinary));
    socket.on("close", () => clearTimeout(this.helloTimer));
  }

  isOpen() {
    return this.socket.readyState === WebSocket.OPEN;
  }

  send(packet) {
    if (!this.isOpen()) return;
    this.socket.send(JSON.stringify({ v: PROTOCOL_VERSION, ...packet }));
  }

  error(code, ref) {
    this.send({ type: "ERROR", code, message: ERRORS[code], ...(ref ? { ref } : {}) });
  }

  close(code, reason) {
    if (this.socket.readyState === WebSocket.OPEN) this.socket.close(code, reason);
  }

  // Token bucket: repõe fichas pelo tempo decorrido e tenta gastar uma.
  // Balde cheio de novo = cliente se acalmou: a sequência de violações zera.
  takeToken() {
    const now = Date.now();
    const { rateBurst, rateRefillPerSec } = this.limits;
    this.tokens = Math.min(rateBurst, this.tokens + ((now - this.lastRefill) / 1000) * rateRefillPerSec);
    this.lastRefill = now;
    if (this.tokens === rateBurst) this.rateViolations = 0;
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }

  // Quadro acima do ritmo: descartado sem ser lido. Só a primeira violação
  // de cada sequência recebe ERROR (responder a cada quadro amplificaria a
  // inundação); quem persiste é desconectado.
  rejectRateLimited() {
    this.rateViolations += 1;
    if (this.rateViolations === 1) this.error("RATE_LIMITED");
    if (this.rateViolations >= this.limits.maxRateViolations && this.isOpen()) {
      this.onRateLimited();
      this.close(CLOSE.RATE_LIMITED, "pacotes demais");
    }
  }

  onFrame(data, isBinary) {
    // Depois que o servidor manda o close (logout, abuso...), a ws ainda
    // emite os quadros que chegarem até o fim do handshake de fechamento;
    // um cliente que ignore o close não pode continuar agindo.
    if (!this.isOpen()) return undefined;
    if (!this.takeToken()) return this.rejectRateLimited();

    let raw;
    try {
      raw = isBinary ? null : JSON.parse(data.toString("utf8"));
    } catch {
      raw = null;
    }

    if (!this.ready) return this.onHandshakeFrame(raw);

    const parsed = clientPacket.safeParse(raw);
    const ref = typeof raw?.id === "string" ? raw.id.slice(0, 64) : undefined;
    if (!parsed.success || parsed.data.type === "HELLO") return this.rejectInvalid(ref);

    const packet = parsed.data;
    if (packet.type === "PING") return this.send({ type: "PONG", ...(packet.id ? { ref: packet.id } : {}) });
    return this.dispatch(packet);
  }

  // Pacote malformado ou fora do schema: ERROR; o reincidente é desconectado.
  rejectInvalid(ref) {
    this.error("BAD_REQUEST", ref);
    this.invalidPackets += 1;
    if (this.invalidPackets >= this.limits.maxInvalidPackets) {
      this.close(CLOSE.POLICY_VIOLATION, "pacotes inválidos demais");
    }
  }

  // Erros inesperados nos handlers viram ERROR INTERNAL para o cliente; no
  // log vai só o tipo do pacote e a mensagem do erro, nunca o pacote.
  async dispatch(packet) {
    try {
      await this.handlers[packet.type](this, packet);
    } catch (err) {
      console.error(`[ws] erro ao tratar ${packet.type}: ${err.message}`);
      this.error("INTERNAL", packet.id);
    }
  }

  onHandshakeFrame(raw) {
    if (raw?.type !== "HELLO") {
      this.error("HELLO_REQUIRED");
      return this.close(CLOSE.POLICY_VIOLATION, "HELLO obrigatório");
    }
    if (raw.v !== PROTOCOL_VERSION) {
      this.error("UNSUPPORTED_VERSION");
      return this.close(CLOSE.UNSUPPORTED_VERSION, "versão não suportada");
    }
    if (!clientPacket.safeParse(raw).success) {
      this.error("BAD_REQUEST");
      return this.close(CLOSE.POLICY_VIOLATION, "HELLO inválido");
    }
    clearTimeout(this.helloTimer);
    this.ready = true;
    return this.send({
      type: "WELCOME",
      userId: this.userId,
      serverTime: new Date().toISOString(),
      limits: {
        maxPayloadBytes: this.limits.maxPayloadBytes,
        maxBodyBytes: this.limits.maxBodyBytes,
      },
    });
  }
}

module.exports = { Connection };
