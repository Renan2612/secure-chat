// Uma sala (B4): chave da sala (ou "aguardando chave"), histórico paginado,
// envio cifrado com estados, entregas decifradas e verificadas, expiração.
// RENDER SEGURO (B-D4): o texto da mensagem é sempre um nó de TEXTO do React
// (escapado); nada de HTML, autolink ou markdown. Inválida vira só o
// marcador "mensagem inválida", sem conteúdo. Tudo em memória.
import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import e2ee from "../crypto/e2ee.js";
import { initialMessages, messagesReducer } from "../chat/messages.js";
import { t } from "../strings.js";
import { roomLabel } from "./Rooms.jsx";

const timeFmt = new Intl.DateTimeFormat("pt-BR", { hour: "2-digit", minute: "2-digit" });
const dateTimeFmt = new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "short" });
const when = (ts) => (ts ? timeFmt.format(new Date(ts)) : "");

function Message({ item, author }) {
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
          {item.exp && <span>{t.expiresAt(dateTimeFmt.format(new Date(item.exp * 1000)))}</span>}
        </div>
      )}
    </li>
  );
}

export default function Chat({ client, ws, events, me, room, onRoomsChanged }) {
  const [messages, dispatch] = useReducer(messagesReducer, initialMessages);
  const [keyState, setKeyState] = useState("loading"); // loading | ok | waiting
  const [notice, setNotice] = useState("");
  const [members, setMembers] = useState({});
  const [draft, setDraft] = useState("");
  const [hasOlder, setHasOlder] = useState(false);
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

  const refreshKey = useCallback(async () => {
    const got = await client.ensureRoomKey(roomId);
    if (current.current !== roomId) return;
    setKeyState(got.ok ? "ok" : "waiting");
    setNotice(client.rotationRequired(roomId) ? t.rotationPending : "");
  }, [client, roomId]);

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
    ws.subscribe(roomId);
    (async () => {
      try {
        await refreshKey();
        const list = await client.members(roomId);
        if (current.current === roomId) setMembers(Object.fromEntries(list.map((m) => [m.id, m.name])));
        await loadHistory();
      } catch {
        if (current.current === roomId) setNotice(t.genericError);
      }
    })();
    return () => ws.unsubscribe(roomId);
  }, [roomId, ws, client, refreshKey, loadHistory]);

  // Eventos do /ws desta sala.
  useEffect(
    () =>
      events.on((event) => {
        if (event.type === "deliver" && event.packet.room === roomId) receive(event.packet).catch(() => {});
        if (event.type !== "room" || event.packet.room !== roomId) return;
        const { kind } = event.packet;
        if (kind === "KEY_READY" || kind === "KEY_ROTATED") refreshKey().catch(() => {});
        if (kind === "ROTATION_PENDING") setNotice(t.rotationPending);
        if (kind === "REMOVED") {
          setKeyState("waiting");
          setNotice(t.removed);
        }
        if (["RENAMED", "OWNER_CHANGED", "RETENTION_CHANGED", "KEY_ROTATED"].includes(kind)) onRoomsChanged();
      }),
    [events, roomId, receive, refreshKey, onRoomsChanged]
  );

  // Expiradas saem da memória e da tela.
  useEffect(() => {
    const timer = setInterval(() => dispatch({ type: "expire", nowMs: Date.now() }), 1000);
    return () => clearInterval(timer);
  }, []);

  const send = async (e) => {
    e.preventDefault();
    const text = draft;
    if (!text.trim() || keyState !== "ok") return;
    setDraft("");
    const cid = crypto.randomUUID();
    // Com retenção na sala, a mensagem PRECISA de exp (seletor de TTL: Parte C).
    const exp = room.retentionSeconds ? e2ee.expFor(room.retentionSeconds) : null;
    dispatch({ type: "sent", me: me.id, cid, text, exp });
    try {
      const body = await client.encrypt(roomId, cid, text, exp);
      const ack = await ws.send({ room: roomId, cid, body });
      dispatch({ type: "acked", me: me.id, cid, id: ack.id, ts: ack.ts });
    } catch (err) {
      dispatch({ type: "failed", me: me.id, cid, code: err.code ?? "ERROR" });
      if (err.code === "ROTATION_PENDING") setNotice(t.rotationPending);
    }
  };

  const tooLong = new TextEncoder().encode(draft).length > e2ee.MAX_TEXT_BYTES;
  const oldest = messages.items.find((i) => i.id !== undefined)?.id;
  return (
    <section className="chat" aria-label={roomLabel(room)}>
      <header className="chat-header">
        <h1>{roomLabel(room)}</h1>
        <div className="badges">
          <span className="chip ok">{t.e2eeBadge}</span>
          <span className={room.nameVerified ? "chip ok" : "chip warn"}>{room.nameVerified ? t.ownerVerifiedBadge : t.nameUnverified}</span>
        </div>
      </header>
      {room.nameTampered && <p className="warning banner" role="alert">{t.nameTampered}</p>}
      {keyState === "waiting" && <p className="warning banner" role="status">{t.waitingKey}</p>}
      {notice && <p className="warning banner" role="status">{notice}</p>}
      <div className="messages">
        {hasOlder && oldest && (
          <button type="button" className="link" onClick={() => loadHistory(oldest)}>{t.loadOlder}</button>
        )}
        <ol aria-live="polite">
          {messages.items.map((item) => (
            <Message key={item.key} item={item} author={members[item.from] ?? t.userFallback(item.from)} />
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
          disabled={keyState !== "ok"}
          rows={2}
        />
        <button className="primary" disabled={keyState !== "ok" || !draft.trim() || tooLong}>{t.send}</button>
      </form>
    </section>
  );
}
