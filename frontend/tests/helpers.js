// Acesso CRU aos registros selados do cofre, só para os testes (inspecionar o
// que foi gravado e simular adulteração). Não existe no código de produção.
import { idbDelete, idbGet, idbPutMany } from "../src/crypto/idb.js";

const RECORDS = ["identity", "state", "trust"];

export const rawRecords = async (userId, replace) => {
  if (replace) {
    await idbDelete(RECORDS.map((r) => `${userId}:${r}`));
    await idbPutMany(Object.entries(replace).map(([r, v]) => [`${userId}:${r}`, v]));
    return replace;
  }
  const out = {};
  for (const r of RECORDS) {
    const value = await idbGet(`${userId}:${r}`);
    if (value !== undefined) out[r] = value;
  }
  return out;
};
