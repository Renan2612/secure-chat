// Criar ou desbloquear o cofre (B2). Sem recuperação: avisado, com
// confirmação explícita, na criação.
import { useEffect, useState } from "react";
import { createVault, hasVault, unlockVault } from "../crypto/vault.js";
import { t } from "../strings.js";

const errorFor = (err) => {
  switch (err?.code) {
    case "SAME_AS_LOGIN":
      return t.passphraseSameAsLogin;
    case "WEAK_PASSPHRASE":
      return t.passphraseWeak;
    case "BAD_PASSPHRASE":
      return t.passphraseWrong;
    case "WRONG_USER":
    case "TRUST_MISMATCH":
    case "STATE_MISMATCH":
    case "WEAK_KDF":
    case "INVALID_KEYSTORE":
      return t.vaultMismatch;
    default:
      return t.genericError;
  }
};

export default function Vault({ user, loginPassword, notice, onUnlocked, onLogout }) {
  const [exists, setExists] = useState(null);
  const [pass, setPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [understood, setUnderstood] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    hasVault(user.id).then(setExists, () => setError(t.genericError));
  }, [user.id]);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    if (!exists && pass !== confirm) return setError(t.passphraseMismatch);
    setBusy(true);
    try {
      const vault = exists
        ? await unlockVault({ userId: user.id, passphrase: pass })
        : await createVault({ userId: user.id, passphrase: pass, loginPassword });
      setPass("");
      setConfirm("");
      return onUnlocked(vault);
    } catch (err) {
      return setError(errorFor(err));
    } finally {
      setBusy(false);
    }
  };

  if (exists === null) return <main className="center"><p>{t.loading}</p></main>;
  return (
    <main className="center">
      <form className="card" onSubmit={submit}>
        <h1>{exists ? t.vaultUnlockTitle : t.vaultCreateTitle}</h1>
        {notice && <p className="warning" role="status">{notice}</p>}
        <p className="muted">{t.vaultExplain}</p>
        {!exists && <p className="warning">{t.vaultNoRecovery}</p>}
        <label>
          {t.passphrase}
          <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} required minLength={10} autoComplete="off" />
        </label>
        {!exists && (
          <>
            <label>
              {t.passphraseConfirm}
              <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required minLength={10} autoComplete="off" />
            </label>
            <p className="muted small">{t.passphraseRule}</p>
            {/* Acréscimo (b): a comparação só é possível na mesma carga de página do login. */}
            {loginPassword === null && <p className="warning small" role="note">{t.passphraseUnchecked}</p>}
            <label className="check">
              <input type="checkbox" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} />
              {t.vaultUnderstood}
            </label>
          </>
        )}
        {error && <p className="error" role="alert">{error}</p>}
        {busy && <p className="muted" role="status">{t.vaultWorking}</p>}
        <button className="primary" disabled={busy || (!exists && !understood)}>{exists ? t.vaultUnlock : t.vaultCreate}</button>
        <button type="button" className="link" onClick={onLogout}>{t.logout}</button>
      </form>
    </main>
  );
}
