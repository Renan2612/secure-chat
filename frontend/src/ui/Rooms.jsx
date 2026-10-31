// Lateral: lista das salas, criar (gera a v1, publica o wrap, mostra o
// convite UMA vez) e entrar com ID e convite (B3). Nome só o assinado pelo
// dono atual; senão "Sala #id (nome não verificado)".
import { useState } from "react";
import e2ee from "../crypto/e2ee.js";
import { t } from "../strings.js";

const MAX = e2ee.MAX_ROOM_NAME_BYTES;
const bytes = (text) => new TextEncoder().encode(text).length;

export const roomLabel = (room) => (room.name === null ? `${t.roomFallback(room.id)} (${t.nameUnverified})` : room.name);

function CreateRoom({ client, onCreated, onClose }) {
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState(null);
  const [copied, setCopied] = useState(false);
  const size = bytes(name.trim());
  const tooLong = size > MAX;

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      setCreated(await client.createRoom(name.trim()));
    } catch (err) {
      setError(err.code === "TEXT_TOO_LONG" ? t.nameTooLong(MAX) : t.genericError);
    } finally {
      setBusy(false);
    }
  };

  if (created) {
    // O convite vive só neste estado do componente: some ao fechar.
    return (
      <div className="dialog" role="dialog" aria-labelledby="invite-title">
        <h2 id="invite-title">{t.inviteTitle}</h2>
        <p className="warning">{t.inviteOnce}</p>
        <dl className="invite">
          <dt>{t.roomId}</dt>
          <dd><code>{created.id}</code></dd>
          <dt>{t.invite}</dt>
          <dd><code>{created.invite}</code></dd>
        </dl>
        <div className="row">
          <button type="button" onClick={() => navigator.clipboard.writeText(`${created.id} ${created.invite}`).then(() => setCopied(true), () => {})}>
            {copied ? t.copied : t.copy}
          </button>
          <button type="button" className="primary" onClick={() => onCreated(created.id)}>{t.done}</button>
        </div>
      </div>
    );
  }
  return (
    <form className="dialog" onSubmit={submit}>
      <h2>{t.createRoom}</h2>
      <label>
        {t.roomName}
        <input value={name} onChange={(e) => setName(e.target.value)} required aria-describedby="name-size" />
      </label>
      <p id="name-size" className={tooLong ? "error small" : "muted small"} aria-live="polite">
        {tooLong ? t.nameTooLong(MAX) : t.nameBytes(size, MAX)}
      </p>
      {error && <p className="error" role="alert">{error}</p>}
      <div className="row">
        <button type="button" onClick={onClose}>{t.cancel}</button>
        <button className="primary" disabled={busy || tooLong || size === 0}>{t.create}</button>
      </div>
    </form>
  );
}

function JoinRoom({ client, onJoined, onClose }) {
  const [id, setId] = useState("");
  const [invite, setInvite] = useState("");
  const [error, setError] = useState("");
  const submit = async (e) => {
    e.preventDefault();
    setError("");
    try {
      await client.joinRoom(Number(id), invite.trim());
      onJoined(Number(id));
    } catch (err) {
      setError(err.code === "BAD_INVITE" ? t.badInvite : t.genericError);
    }
  };
  return (
    <form className="dialog" onSubmit={submit}>
      <h2>{t.joinRoom}</h2>
      <label>
        {t.roomId}
        <input inputMode="numeric" pattern="[1-9][0-9]{0,9}" value={id} onChange={(e) => setId(e.target.value)} required />
      </label>
      <label>
        {t.invite}
        <input value={invite} onChange={(e) => setInvite(e.target.value)} required maxLength={128} autoComplete="off" />
      </label>
      {error && <p className="error" role="alert">{error}</p>}
      <div className="row">
        <button type="button" onClick={onClose}>{t.cancel}</button>
        <button className="primary">{t.join}</button>
      </div>
    </form>
  );
}

export default function Rooms({ client, rooms, selected, onSelect, onChanged }) {
  const [dialog, setDialog] = useState(null);
  const done = async (roomId) => {
    setDialog(null);
    await onChanged();
    onSelect(roomId);
  };
  return (
    <nav className="sidebar" aria-label={t.rooms}>
      <h2>{t.rooms}</h2>
      {rooms.length === 0 && <p className="muted small">{t.noRooms}</p>}
      <ul className="rooms">
        {rooms.map((room) => (
          <li key={room.id}>
            <button type="button" className={room.id === selected ? "room active" : "room"} aria-current={room.id === selected ? "page" : undefined} onClick={() => onSelect(room.id)}>
              <span className={room.name === null ? "muted" : ""}>{roomLabel(room)}</span>
              {room.unread > 0 && <span className="chip">{room.unread}</span>}
            </button>
          </li>
        ))}
      </ul>
      <div className="row">
        <button type="button" className="primary" onClick={() => setDialog("create")}>{t.createRoom}</button>
        <button type="button" onClick={() => setDialog("join")}>{t.joinRoom}</button>
      </div>
      {dialog === "create" && <CreateRoom client={client} onCreated={done} onClose={() => setDialog(null)} />}
      {dialog === "join" && <JoinRoom client={client} onJoined={done} onClose={() => setDialog(null)} />}
    </nav>
  );
}
