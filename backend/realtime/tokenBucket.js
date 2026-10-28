// Balde de fichas: até `burst` de uma vez, repostas a `refillPerSec`.
// Parâmetro inválido lança erro: um NaN faria take() aceitar tudo (sem limite).
const valid = (n) => Number.isFinite(n) && n > 0;

class TokenBucket {
  constructor(burst, refillPerSec) {
    if (!valid(burst) || !valid(refillPerSec)) {
      throw new Error(`TokenBucket: rajada e reposição devem ser números > 0 (${burst}, ${refillPerSec})`);
    }
    this.burst = burst;
    this.refillPerSec = refillPerSec;
    this.tokens = burst;
    this.last = Date.now();
  }

  refill() {
    const now = Date.now();
    // Relógio que volta (ajuste de hora) não tira nem dá fichas.
    const elapsed = Math.max(0, now - this.last);
    this.tokens = Math.min(this.burst, this.tokens + (elapsed / 1000) * this.refillPerSec);
    this.last = now;
  }

  take() {
    this.refill();
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }

  isFull() {
    this.refill();
    return this.tokens === this.burst;
  }
}

module.exports = { TokenBucket };
