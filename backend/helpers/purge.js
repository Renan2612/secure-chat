// Expurgo das mensagens expiradas (Etapa 5, A1): a cada `intervalMs`
// (padrão 60 s, PURGE_INTERVAL_MS), apaga do banco as linhas cujo
// expires_at já passou, pelo relógio do servidor. Não registra contagens
// nem ids no log (seriam metadado de uso): só falhas, sem dados.
//
// Limites (docs/06-privacidade.md): um servidor malicioso pode simplesmente
// não apagar; as páginas do Postgres e os backups podem guardar a linha até
// o VACUUM (e além, nos backups). O histórico e a entrega já ignoram a
// mensagem vencida mesmo antes do expurgo.
const DEFAULT_INTERVAL_MS = 60 * 1000;

const createPurger = ({ pool, clock, intervalMs = DEFAULT_INTERVAL_MS, skip = false }) => {
  let timer = null;
  const purgeNow = async () => {
    if (skip) return 0; // só a mutação do verify-e2ee.sh (servidor que não apaga)
    const { rowCount } = await pool.query("DELETE FROM messages WHERE expires_at <= to_timestamp($1::double precision)", [
      clock.nowMs() / 1000,
    ]);
    return rowCount;
  };
  const tick = () =>
    purgeNow().catch((err) => console.error(`[purge] falha no expurgo: code=${err.code ?? "-"} ${err.message}`));
  return {
    purgeNow,
    start() {
      if (timer) return;
      timer = setInterval(tick, intervalMs);
      timer.unref();
    },
    stop() {
      clearInterval(timer);
      timer = null;
    },
  };
};

// PURGE_INTERVAL_MS: inteiro entre 1 s e 1 h; inválido → não sobe.
const purgeIntervalFromEnv = (raw = process.env.PURGE_INTERVAL_MS) => {
  if (raw === undefined || raw === "") return DEFAULT_INTERVAL_MS;
  if (!/^[0-9]{1,7}$/.test(raw) || Number(raw) < 1000 || Number(raw) > 3600 * 1000) {
    throw new Error("PURGE_INTERVAL_MS deve ser um inteiro entre 1000 e 3600000 (ms)");
  }
  return Number(raw);
};

module.exports = { createPurger, purgeIntervalFromEnv, DEFAULT_INTERVAL_MS };
