// Balde de fichas: até `burst` de uma vez, repostas a `refillPerSec`.
class TokenBucket {
  constructor(burst, refillPerSec) {
    this.burst = burst;
    this.refillPerSec = refillPerSec;
    this.tokens = burst;
    this.last = Date.now();
  }

  refill() {
    const now = Date.now();
    this.tokens = Math.min(this.burst, this.tokens + ((now - this.last) / 1000) * this.refillPerSec);
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
