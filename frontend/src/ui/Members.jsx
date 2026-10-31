// Painel da sala (C1, C2): membros com o selo de confiança, número de
// segurança e confirmação, pendentes à espera da chave, e as ações de
// composição (remover, tornar dono, sair, convite novo, banidos, renomear,
// retenção). Nomes e ids vêm do servidor e são exibidos só como TEXTO.
import { useCallback, useEffect, useState } from "react";
import e2ee from "../crypto/e2ee.js";
import { t } from "../strings.js";

const MAX_NAME = e2ee.MAX_ROOM_NAME_BYTES;
const RETENTION_OPTIONS = [null, 60, 3600, 86400, 604800];
const RETENTION_PRESET = { 60: "1min", 3600: "1h", 86400: "24h", 604800: "7d" };
const retentionLabel = (s) => (s === null ? t.retentionOff : t.ttlOptions[RETENTION_PRESET[s]] ?? `${s} s`);
const TRUST_CHIP = { verified: "chip ok", unverified: "chip warn", changed: "chip danger", unknown: "chip", unchecked: "chip danger" };

function Safety({ client, member, onConfirmed }) {
  const [shown, setShown] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    client.safety(member.id).then(setShown, () => setError(t.genericError));
  }, [client, member.id]);
  if (error) return <p className="error small">{error}</p>;
  if (!shown) return <p className="muted small">{t.loading}</p>;
  return (
    <div className="safety">
      <p className="muted small">{t.safetyHelp}</p>
      <p className="digits" aria-label={t.safetyNumber}>{shown.number}</p>
      <button
        type="button"
        className="primary"
        onClick={() =>
          client.confirm(member.id, shown.fingerprint).then(onConfirmed, () => {
            // A chave mudou entre a exibição e o clique: mostra o número NOVO.
            setError(t.fingerprintChanged);
            client.safety(member.id).then(setShown, () => setError(t.genericError));
          })
        }
      >
        {t.markVerified}
      </button>
    </div>
  );
}

export default function Members({ client, me, room, pending, onChanged, onNotice, onClose }) {
  const [members, setMembers] = useState([]);
  const [open, setOpen] = useState(null); // id com o número de segurança aberto
  const [secret, setSecret] = useState(""); // convite mostrado UMA vez
  const [bans, setBans] = useState(null);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const isOwner = room.ownerId === me.id;

  const load = useCallback(async () => {
    const list = await client.members(room.id);
    for (const m of list) if (m.id !== me.id) await client.observe(m.id).catch(() => null);
    setMembers(list.map((m) => ({ ...m, trust: client.trustOf(m.id) })));
  }, [client, room.id, me.id]);

  useEffect(() => {
    load().catch(() => onNotice(t.genericError));
  }, [load, onNotice, pending]);

  // Executa uma ação, mostra o erro em texto e recarrega.
  const run = async (action, messages = {}) => {
    setBusy(true);
    try {
      return await action();
    } catch (err) {
      onNotice(messages[err.code] ?? t.genericError);
      return undefined;
    } finally {
      setBusy(false);
      await load().catch(() => {});
      onChanged();
    }
  };

  const label = (m) => t.authorLabel(m.name, m.id);
  const nameBytes = new TextEncoder().encode(name.trim()).length;

  return (
    <aside className="panel" aria-label={t.showMembers}>
      <button type="button" className="mobile-only" onClick={onClose}>{t.hideMembers}</button>
      <h2>{t.members}</h2>
      <ul className="members">
        {members.map((m) => (
          <li key={m.id}>
            <div className="member">
              <span>
                {m.id === me.id ? `${t.you} · #${m.id}` : label(m)}
                {m.id === room.ownerId && <span className="chip"> {t.owner}</span>}
              </span>
              {m.id !== me.id && <span className={TRUST_CHIP[m.trust]}>{t.trust[m.trust]}</span>}
            </div>
            {m.id !== me.id && (
              <div className="row">
                {m.trust !== "unknown" && (
                  <button type="button" aria-expanded={open === m.id} onClick={() => setOpen(open === m.id ? null : m.id)}>
                    {t.safetyNumber}
                  </button>
                )}
                {isOwner && (
                  <>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() =>
                        window.confirm(t.confirmRemove(label(m))) &&
                        run(async () => {
                          const { invite, saved } = await client.kick(room.id, m.id);
                          setSecret(`${t.removedInvite} ${invite}`);
                          if (!saved) onNotice(t.kickNotSaved);
                          // Rotaciona SEMPRE depois de remover (o removido tem a chave atual).
                          const r = await client.rotate(room.id).catch(() => null);
                          if (!r) onNotice(t.rotateFailed);
                          else if (r.rotated) onNotice(r.left.length ? `${t.rotated(r.version)} ${t.rotatedLeft(r.left)}` : t.rotated(r.version));
                          else if (r.reason === "stale") onNotice(t.rotateStale);
                        })
                      }
                    >
                      {t.remove}
                    </button>
                    <button type="button" disabled={busy} onClick={() => run(() => client.transferOwner(room.id, m.id), { TARGET_NO_KEY: t.targetNoKey })}>
                      {t.makeOwner}
                    </button>
                  </>
                )}
              </div>
            )}
            {open === m.id && (
              <Safety
                client={client}
                member={m}
                onConfirmed={() => {
                  setOpen(null);
                  load().catch(() => {});
                  client.distribute(room.id).catch(() => onNotice(t.genericError));
                }}
              />
            )}
          </li>
        ))}
      </ul>

      {pending.length > 0 && (
        <section aria-labelledby="pending-title">
          <h3 id="pending-title">{t.pendingTitle}</h3>
          <p className="muted small">{t.pendingHelp}</p>
          <ul className="members">
            {pending.map((p) => (
              <li key={p.userId} className="member">
                <span>
                  {t.authorLabel(p.name, p.userId)} <code className="small">{p.fingerprint.slice(0, 16)}</code>
                </span>
                <div className="row">
                  <button type="button" onClick={() => setOpen(p.userId)}>{t.review}</button>
                  <button type="button" className="primary" disabled={busy} onClick={() => run(() => client.approve(room.id, p.userId))}>
                    {t.deliverKey}
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {secret && (
        <p className="warning" role="status">
          {secret}
        </p>
      )}

      {isOwner && (
        <section className="settings">
          <button type="button" disabled={busy} onClick={() => run(async () => setSecret(`${t.inviteNew} ${await client.rotateInvite(room.id)}`))}>
            {t.newInvite}
          </button>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              run(async () => {
                await client.rename(room.id, name.trim());
                setName("");
                onNotice(t.renamed);
              });
            }}
          >
            <label>
              {t.rename}
              <input value={name} onChange={(e) => setName(e.target.value)} aria-describedby="rename-size" />
            </label>
            <p id="rename-size" className={nameBytes > MAX_NAME ? "error small" : "muted small"} aria-live="polite">
              {nameBytes > MAX_NAME ? t.nameTooLong(MAX_NAME) : t.nameBytes(nameBytes, MAX_NAME)}
            </p>
            <button disabled={busy || nameBytes === 0 || nameBytes > MAX_NAME}>{t.rename}</button>
          </form>

          <label>
            {t.retention}
            <select
              value={room.retentionSeconds ?? ""}
              disabled={busy}
              onChange={(e) => run(() => client.setRetention(room.id, e.target.value === "" ? null : Number(e.target.value)))}
            >
              {RETENTION_OPTIONS.map((s) => (
                <option key={s ?? "off"} value={s ?? ""}>{retentionLabel(s)}</option>
              ))}
            </select>
          </label>

          <div>
            <button type="button" onClick={() => client.bans(room.id).then(setBans, () => onNotice(t.genericError))}>{t.bans}</button>
            {bans && bans.length === 0 && <p className="muted small">{t.noBans}</p>}
            {bans && bans.length > 0 && (
              <ul className="members">
                {bans.map((b) => (
                  <li key={b.userId} className="member">
                    <span>{t.authorLabel(b.name, b.userId)}</span>
                    <button type="button" onClick={() => run(async () => {
                      await client.unban(room.id, b.userId);
                      setBans(await client.bans(room.id));
                    })}>{t.unban}</button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>
      )}

      <button
        type="button"
        className="danger"
        disabled={busy}
        onClick={() => window.confirm(t.confirmLeave) && run(() => client.leave(room.id), { OWNER_MUST_TRANSFER: t.ownerMustTransfer })}
      >
        {t.leaveRoom}
      </button>
    </aside>
  );
}
