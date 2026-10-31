// Mensagens de UMA sala, em memória (nada vai a disco). Redutor puro:
//   sent / acked / failed     o próprio envio (sending → confirmed | failed)
//   received                  entrega ou histórico, já passado pelo
//                             receptor E2EE (client.accept)
//   expire                    tira da memória as que venceram
//   reset                     bloqueio do cofre, logout, troca de sala
// Chave = `${remetente}:${cid}` (a mesma deduplicação do receptor). Uma
// inválida NUNCA carrega texto, nunca substitui uma aceita, e é substituída
// pela legítima de mesmo (remetente, cid).
export const initialMessages = Object.freeze({ items: [] });

const STATUS_OF = { invalid: "invalid", missing_key: "no_key", untrusted: "untrusted", error: "error" };

const sortItems = (items) =>
  [...items].sort((a, b) => {
    if (a.id === undefined && b.id === undefined) return 0;
    if (a.id === undefined) return 1;
    if (b.id === undefined) return -1;
    return a.id - b.id;
  });

const upsert = (state, key, make) => {
  const existing = state.items.find((i) => i.key === key);
  const next = make(existing);
  if (next === existing) return state;
  const others = state.items.filter((i) => i.key !== key);
  return { items: sortItems(next ? [...others, next] : others) };
};

export const messagesReducer = (state, action) => {
  switch (action.type) {
    case "sent":
      return upsert(state, `${action.me}:${action.cid}`, () => ({
        key: `${action.me}:${action.cid}`,
        cid: action.cid,
        from: action.me,
        mine: true,
        status: "sending",
        text: action.text,
        exp: action.exp,
      }));
    case "acked":
      return upsert(state, `${action.me}:${action.cid}`, (item) =>
        item ? { ...item, status: "confirmed", id: action.id, ts: action.ts } : item
      );
    case "failed":
      return upsert(state, `${action.me}:${action.cid}`, (item) => (item ? { ...item, status: "failed", reason: action.code } : item));
    case "received": {
      const { packet, result, me } = action;
      const key = `${packet.from}:${packet.cid}`;
      if (result.status === "duplicate" || result.status === "expired") return state;
      const base = { key, cid: packet.cid, from: packet.from, id: packet.id, ts: packet.ts, mine: packet.from === me };
      if (result.status === "ok") {
        return upsert(state, key, (item) => ({
          ...base,
          status: item?.mine && item.status !== "failed" ? "confirmed" : item?.mine ? item.status : "ok",
          text: result.text,
          verified: result.verified,
          exp: result.exp,
        }));
      }
      const status = STATUS_OF[result.status] ?? "invalid";
      return upsert(state, key, (item) => {
        if (item && (item.status === "ok" || item.status === "confirmed" || item.mine)) return item;
        return { ...base, status, reason: result.reason ?? result.trust ?? result.kv };
      });
    }
    case "expire": {
      const items = state.items.filter((i) => !(i.exp != null && i.exp * 1000 <= action.nowMs));
      return items.length === state.items.length ? state : { items };
    }
    case "reset":
      return initialMessages;
    default:
      return state;
  }
};
