// Fluxo da aplicação: sessão (GET /me) → login/cadastro → cofre (criar ou
// desbloquear) → salas e chat. Bloqueio do cofre por inatividade (15 min) e
// no logout: as chaves e as mensagens decifradas saem da memória.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createApi } from "../api.js";
import { createClient } from "../chat/client.js";
import { WsSession } from "../chat/wsSession.js";
import { t } from "../strings.js";
import Auth from "./Auth.jsx";
import Vault from "./Vault.jsx";
import Rooms from "./Rooms.jsx";
import Chat from "./Chat.jsx";

const IDLE_LOCK_MS = 15 * 60 * 1000;
const ACTIVITY = ["pointerdown", "keydown", "wheel", "touchstart"];

// Rota mínima por hash: #/sala/<id>.
const roomFromHash = () => {
  const m = /^#\/sala\/([1-9][0-9]{0,9})$/.exec(window.location.hash);
  return m ? Number(m[1]) : null;
};

// Distribui os eventos do /ws a quem está na tela.
const createEvents = () => {
  const listeners = new Set();
  return {
    on(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    emit(event) {
      for (const fn of listeners) fn(event);
    },
  };
};

const KEYS_ERROR = { KEYS_MISMATCH: t.keysMismatch };

export default function App() {
  const api = useMemo(() => createApi(), []);
  const [user, setUser] = useState(undefined); // undefined = verificando; null = sem sessão
  const loginPassword = useRef(null);
  const [vault, setVault] = useState(null);
  const [session, setSession] = useState(null); // { client, ws, events }
  const [rooms, setRooms] = useState([]);
  const [selected, setSelected] = useState(roomFromHash());
  const [status, setStatus] = useState("connecting");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    api("get", "/me").then(
      (res) => setUser(res.status === 200 ? res.body : null),
      () => setUser(null)
    );
  }, [api]);

  useEffect(() => {
    const onHash = () => setSelected(roomFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // Bloqueia: fecha o /ws, apaga as chaves e o texto decifrado da memória.
  const lock = useCallback(
    (why = "") => {
      session?.ws.close();
      vault?.lock();
      setSession(null);
      setVault(null);
      setRooms([]);
      setNotice(why);
    },
    [session, vault]
  );

  const logout = useCallback(async () => {
    lock();
    loginPassword.current = null;
    await api("post", "/logout").catch(() => {});
    setUser(null);
  }, [api, lock]);

  const refreshRooms = useCallback(async () => {
    if (session) setRooms(await session.client.listRooms());
  }, [session]);

  // Cofre aberto → cliente E2EE, chaves públicas no diretório, /ws.
  const unlocked = async (opened) => {
    loginPassword.current = null; // não precisa mais (o cofre já existe)
    setNotice(opened.trustReset ? t.trustReset : "");
    const client = createClient({ api, me: user, vault: opened });
    try {
      await client.registerKeys();
    } catch (err) {
      opened.lock();
      setNotice(KEYS_ERROR[err.code] ?? t.genericError);
      return;
    }
    const events = createEvents();
    const ws = new WsSession({
      url: `wss://${window.location.host}/ws`,
      onEvent: (event) => {
        if (event.type === "status") setStatus(event.status);
        events.emit(event);
      },
    });
    ws.connect();
    setVault(opened);
    setSession({ client, ws, events });
    setRooms(await client.listRooms());
  };

  // Sessão encerrada no servidor (logout em outra aba, expirou): volta ao login.
  useEffect(() => {
    if (status === "signed-out") {
      lock();
      setUser(null);
    }
  }, [status, lock]);

  // Inatividade: 15 min sem interação → bloqueio.
  useEffect(() => {
    if (!vault) return undefined;
    let timer = setTimeout(() => lock(t.lockedIdle), IDLE_LOCK_MS);
    const reset = () => {
      clearTimeout(timer);
      timer = setTimeout(() => lock(t.lockedIdle), IDLE_LOCK_MS);
    };
    for (const name of ACTIVITY) window.addEventListener(name, reset, { passive: true });
    return () => {
      clearTimeout(timer);
      for (const name of ACTIVITY) window.removeEventListener(name, reset);
    };
  }, [vault, lock]);

  const select = (roomId) => {
    window.location.hash = `#/sala/${roomId}`;
  };

  if (user === undefined) return <main className="center"><p>{t.loading}</p></main>;
  if (user === null) {
    return (
      <Auth
        api={api}
        onLoggedIn={(me, password) => {
          loginPassword.current = password;
          setUser(me);
        }}
      />
    );
  }
  if (!session) {
    return <Vault user={user} loginPassword={loginPassword.current} notice={notice} onUnlocked={unlocked} onLogout={logout} />;
  }
  const room = rooms.find((r) => r.id === selected);
  return (
    <div className="layout">
      <aside className="side">
        <div className="whoami">
          <strong>{user.name}</strong>
          <span className={status === "ready" ? "chip ok" : "chip warn"} role="status">{t.status[status] ?? status}</span>
        </div>
        <Rooms client={session.client} rooms={rooms} selected={selected} onSelect={select} onChanged={refreshRooms} />
        <div className="row">
          <button type="button" onClick={() => lock()}>{t.lock}</button>
          <button type="button" onClick={logout}>{t.logout}</button>
        </div>
      </aside>
      <main className="main">
        {notice && <p className="warning banner" role="status">{notice}</p>}
        {room ? (
          <Chat key={room.id} client={session.client} ws={session.ws} events={session.events} me={user} room={room} onRoomsChanged={refreshRooms} />
        ) : (
          <p className="center muted">{t.selectRoom}</p>
        )}
      </main>
    </div>
  );
}
