// Uma sala (B4, C1–C3): chave da sala (ou "aguardando chave"), histórico
// paginado, envio cifrado com estados e expiração escolhida (C2), entregas
// decifradas e verificadas, e os eventos da sala: entrega da chave a
// pendentes, rotação automática, novo dono, remoção.
// RENDER SEGURO (B-D4): o texto da mensagem é sempre um nó de TEXTO do React
// (escapado); nada de HTML, autolink ou markdown. Inválida vira só o
// marcador "mensagem inválida", sem conteúdo. Tudo em memória.
import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import e2ee from "../crypto/e2ee.js";
import { initialMessages, messagesReducer } from "../chat/messages.js";
import { t } from "../strings.js";
import { roomLabel } from "./Rooms.jsx";
import Members from "./Members.jsx";

const timeFmt = new Intl.DateTimeFormat("pt-BR", { hour: "2-digit", minute: "2-digit" });
const when = (ts) => (ts ? timeFmt.format(new Date(ts)) : "");
const TTL_KEYS = ["off", "1min", "1h", "24h", "7d"];

// "2 min 05 s", "3 h 10 min", "6 d 23 h": o bastante para uma contagem regressiva.
const remaining = (seconds) => {
  const s = Math.max(0, Math.floor(seconds));
  if (s < 3600) return `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, "0")} s`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
  return `${Math.floor(s / 86400)} d ${Math.floor((s % 86400) / 3600)} h`;
};

function Message({ item, author, nowMs }) {
  let body;
  if (item.status === "invalid") body = <em className="marker">{t.invalidMessage}</em>;
  else if (item.status === "no_key") body = <em className="marker">{t.noKeyMessage}</em>;
  else if (item.status === "untrusted") body = <em className="marker">{t.untrustedMessage}</em>;
  else body = <p className="text">{item.text}</p>;
  const state =
    item.status === "sending" ? t.sending : item.status === "failed" ? `${t.failed}: ${t.sendErrors[item.reason] ?? t.genericError}` : "";
  return (
    <li className={item.mine ? "bubble mine" : "bubble"}>
      <div className="meta">
        <span className="author">{item.mine ? t.you : author}</span>
        {!item.mine && item.status === "ok" && <span className={item.verified ? "chip ok" : "chip warn"}>{item.verified ? t.verified : t.unverified}</span>}
        <span className="muted">{when(item.ts)}</span>
      </div>
      {body}
      {(state || item.exp) && (
        <div className="meta muted small">
          {state && <span className={item.status === "failed" ? "error" : ""}>{state}</span>}
          {item.exp && <span>{t.remaining(remaining(item.exp - nowMs / 1000))}</span>}
        </div>
      )}
    </li>
  );
}

export default function Chat({ client, ws, events, me, room, onRoomsChanged, onOpenRooms }) {
  const [messages, dispatch] = useReducer(messagesReducer, initialMessages);
  const [keyState, setKeyState] = useState("loading"); // loading | ok | waiting | removed
  const [notice, setNotice] = useState("");
  const [members, setMembers] = useState({});
  const [changed, setChanged] = useState([]); // membros com CHAVE ALTERADA
  const [pending, setPending] = useState([]); // aguardando aprovação
  const [panel, setPanel] = useState(false);
  const [draft, setDraft] = useState("");
  const [ttl, setTtl] = useState("off");
  const [hasOlder, setHasOlder] = useState(false);
  const [nowMs, setNowMs] = useState(Date.now());
  const roomId = room.id;
  const current = useRef(roomId);
  current.current = roomId;

  const receive = useCallback(
    async (packet) => {
      const result = await client.accept(packet);
      if (current.current === packet.room) dispatch({ type: "received", me: me.id, packet, result });
    },
    [client, me.id]
  );

  const refreshMembers = useCallback(async () => {
    const list = await client.members(roomId);
    for (const m of list) if (m.id !== me.id) await client.observe(m.id).catch(() => null);
    if (current.current !== roomId) return;
    setMembers(Object.fromEntries(list.map((m) => [m.id, m.name])));
    setChanged(list.filter((m) => m.id !== me.id && client.trustOf(m.id) === "changed"));
  }, [client, roomId, me.id]);

  const distribute = useCallback(async () => {
    const r = await client.distribute(roomId);
    if (current.current === roomId) setPending(r.awaitingApproval);
  }, [client, roomId]);

  const rotateIfNeeded = useCallback(async () => {
    if (!client.rotationRequired(roomId)) return;
    const r = await client.autoRotate(roomId);
    if (r.rotated) setNotice(r.left.length ? `${t.rotated(r.version)} ${t.rotatedLeft(r.left)}` : t.rotated(r.version));
  }, [client, roomId]);

  const refreshKey = useCallback(async () => {
    const got = await client.ensureRoomKey(roomId);
    if (current.current !== roomId) return;
    setKeyState(got.ok ? "ok" : "waiting");
    if (got.ok) {
      await rotateIfNeeded();
      await distribute();
    }
    if (client.rotationRequired(roomId)) setNotice(got.ok ? t.rotationPending : t.roomLocked);
    else setNotice((n) => (n === t.rotationPending || n === t.roomLocked ? "" : n));
  }, [client, roomId, rotateIfNeeded, distribute]);

  const loadHistory = useCallback(
    async (before) => {
      const page = await client.history(roomId, { before, limit: 50 });
      if (current.current !== roomId) return;
      setHasOlder(page.length === 50);
      for (const { packet, result } of page) dispatch({ type: "received", me: me.id, packet, result });
    },
    [client, roomId, me.id]
  );

  // Troca de sala: zera a memória, busca a chave, inscreve e carrega.
  useEffect(() => {
    dispatch({ type: "reset" });
    setKeyState("loading");
    setNotice("");
    setPending([]);
    ws.subscribe(roomId);
    (async () => {
      try {
        if (await client.ensureOwnerSignature(roomId).catch(() => false)) onRoomsChanged();
        await refreshMembers();
        await refreshKey();
        await loadHistory();
      } catch {
        if (current.current === roomId) setNotice(t.genericError);
      }
    })();
    return () => ws.unsubscribe(roomId);
  }, [roomId, ws, client, refreshKey, refreshMembers, loadHistory, onRoomsChanged]);

  // Eventos do /ws desta sala.
  useEffect(
    () =>
      events.on((event) => {
        if (event.type === "deliver" && event.packet.room === roomId) receive(event.packet).catch(() => {});
        if (event.type !== "room" || event.packet.room !== roomId) return;
        const { kind } = event.packet;
        const soft = (p) => p.catch(() => setNotice(t.genericError));
        if (kind === "KEY_READY" || kind === "KEY_ROTATED") soft(refreshKey());
        if (kind === "KEY_PENDING") soft(distribute().then(refreshMembers));
        if (kind === "ROTATION_PENDING") {
          setNotice(t.rotationPending);
          soft(refreshKey());
        }
        if (kind === "REMOVED") {
          setKeyState("removed");
          setNotice(t.removed);
        }
        if (kind === "OWNER_CHANGED" && event.packet.ownerId === me.id) {
          soft(client.ensureOwnerSignature(roomId).then((done) => done && setNotice(t.resigned)));
        }
        if (["RENAMED", "OWNER_CHANGED", "RETENTION_CHANGED", "KEY_ROTATED"].includes(kind)) onRoomsChanged();
      }),
    [events, roomId, receive, refreshKey, refreshMembers, distribute, onRoomsChanged, client, me.id]
  );

  // Relógio da tela: contagem regressiva e remoção das vencidas da memória.
  useEffect(() => {
    const timer = setInterval(() => {
      const now = Date.now();
      setNowMs(now);
      dispatch({ type: "expire", nowMs: now });
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // C2: com retenção na sala, a expiração é obrigatória e limitada por ela.
  const ttlSeconds = () => {
    const chosen = ttl === "off" ? null : e2ee.TTL_PRESETS[ttl];
    if (!room.retentionSeconds) return chosen;
    return Math.min(chosen ?? room.retentionSeconds, room.retentionSeconds);
  };

  const canSend = keyState === "ok" && changed.length === 0 && !client.rotationRequired(roomId);

  const send = async (e) => {
    e.preventDefault();
    const text = draft;
    if (!text.trim() || !canSend) return;
    setDraft("");
    const cid = crypto.randomUUID();
    const exp = e2ee.expFor(ttlSeconds());
    dispatch({ type: "sent", me: me.id, cid, text, exp });
    try {
      const body = await client.encrypt(roomId, cid, text, exp);
      const ack = await ws.send({ room: roomId, cid, body });
      dispatch({ type: "acked", me: me.id, cid, id: ack.id, ts: ack.ts });
    } catch (err) {
      dispatch({ type: "failed", me: me.id, cid, code: err.code ?? "ERROR" });
      if (err.code === "ROTATION_PENDING") refreshKey().catch(() => {});
    }
  };

  const tooLong = new TextEncoder().encode(draft).length > e2ee.MAX_TEXT_BYTES;
  const oldest = messages.items.find((i) => i.id !== undefined)?.id;
  const capped = room.retentionSeconds && (ttl === "off" || e2ee.TTL_PRESETS[ttl] > room.retentionSeconds);
  return (
    <div className={panel ? "chat-wrap with-panel" : "chat-wrap"}>
      <section className="chat" aria-label={roomLabel(room)}>
        <header className="chat-header">
          <button type="button" className="mobile-only" onClick={onOpenRooms}>{t.openRooms}</button>
          <h1>{roomLabel(room)}</h1>
          <div className="badges">
            <span className="chip ok">{t.e2eeBadge}</span>
            <span className={room.nameVerified ? "chip ok" : "chip warn"}>{room.nameVerified ? t.ownerVerifiedBadge : t.nameUnverified}</span>
            <button type="button" aria-expanded={panel} onClick={() => setPanel(!panel)}>{panel ? t.hideMembers : t.showMembers}</button>
          </div>
        </header>
        {room.nameTampered && <p className="warning banner" role="alert">{t.nameTampered}</p>}
        {changed.map((m) => (
          <p key={m.id} className="danger banner" role="alert">
            {t.keyChangedBlock(t.authorLabel(m.name, m.id))}{" "}
            <button type="button" onClick={() => setPanel(true)}>{t.review}</button>
          </p>
        ))}
        {keyState === "waiting" && <p className="warning banner" role="status">{t.waitingKey}</p>}
        {notice && <p className="warning banner" role="status">{notice}</p>}
        <div className="messages">
          {hasOlder && oldest && (
            <button type="button" className="link" onClick={() => loadHistory(oldest)}>{t.loadOlder}</button>
          )}
          <ol aria-live="polite" aria-relevant="additions">
            {messages.items.map((item) => (
              <Message key={item.key} item={item} nowMs={nowMs} author={t.authorLabel(members[item.from], item.from)} />
            ))}
          </ol>
        </div>
        <form className="composer" onSubmit={send}>
          <label className="sr-only" htmlFor="composer">{t.composer}</label>
          <textarea
            id="composer"
            value={draft}
            placeholder={t.composer}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) send(e);
            }}
            disabled={!canSend}
            rows={2}
          />
          <label className="ttl">
            {t.ttl}
            <select value={ttl} onChange={(e) => setTtl(e.target.value)} disabled={!canSend}>
              {TTL_KEYS.map((k) => (
                <option key={k} value={k}>{t.ttlOptions[k]}</option>
              ))}
            </select>
            {capped && <span className="muted small">{t.ttlCapped(room.retentionSeconds)}</span>}
          </label>
          <button className="primary" disabled={!canSend || !draft.trim() || tooLong}>{t.send}</button>
        </form>
      </section>
      {panel && (
        <Members client={client} me={me} room={room} pending={pending} onChanged={() => { onRoomsChanged(); refreshMembers().catch(() => {}); }} onNotice={setNotice} onClose={() => setPanel(false)} />
      )}
    </div>
  );
}
