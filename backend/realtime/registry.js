// Registro em memória das conexões abertas: por usuário (limite de conexões,
// derrubar tudo no logout). Cada conexão é uma instância de Connection.
class ConnectionRegistry {
  constructor() {
    this.byUser = new Map(); // userId → Set<conexão>
    this.all = new Set();
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
}

module.exports = { ConnectionRegistry };
