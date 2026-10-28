// Registro em memória das conexões abertas: por usuário (limite de conexões,
// derrubar tudo no logout) e por sala (para quem entregar cada mensagem —
// nunca broadcast global). Cada conexão é uma instância de Connection.
class ConnectionRegistry {
  constructor() {
    this.byUser = new Map(); // userId → Set<conexão>
    this.byRoom = new Map(); // sala → Set<conexão inscrita>
    this.all = new Set();
    this.cooldownUntil = new Map(); // userId → instante (ms) do fim da quarentena
  }

  startCooldown(userId, ms) {
    this.cooldownUntil.set(userId, Date.now() + ms);
  }

  inCooldown(userId) {
    const until = this.cooldownUntil.get(userId);
    if (until === undefined) return false;
    if (Date.now() < until) return true;
    this.cooldownUntil.delete(userId);
    return false;
  }

  get size() {
    return this.all.size;
  }

  countForUser(userId) {
    return this.byUser.get(userId)?.size ?? 0;
  }

  add(conn) {
    this.all.add(conn);
    if (!this.byUser.has(conn.userId)) this.byUser.set(conn.userId, new Set());
    this.byUser.get(conn.userId).add(conn);
  }

  remove(conn) {
    for (const room of conn.rooms) this.unsubscribe(conn, room);
    this.all.delete(conn);
    const own = this.byUser.get(conn.userId);
    if (own) {
      own.delete(conn);
      if (own.size === 0) this.byUser.delete(conn.userId);
    }
  }

  forUser(userId) {
    return [...(this.byUser.get(userId) ?? [])];
  }

  subscribe(conn, room) {
    if (!this.byRoom.has(room)) this.byRoom.set(room, new Set());
    this.byRoom.get(room).add(conn);
    conn.rooms.add(room);
  }

  unsubscribe(conn, room) {
    conn.rooms.delete(room);
    const subs = this.byRoom.get(room);
    if (subs) {
      subs.delete(conn);
      if (subs.size === 0) this.byRoom.delete(room);
    }
  }

  subscribers(room) {
    return [...(this.byRoom.get(room) ?? [])];
  }
}

module.exports = { ConnectionRegistry };
