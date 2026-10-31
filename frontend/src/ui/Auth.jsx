// Login e cadastro (B2). A senha de login vai ao servidor (HTTPS); a de
// cifragem, que vem depois, não.
import { useState } from "react";
import { t } from "../strings.js";

const errorFor = (status, mode) => {
  if (status === 401) return t.badCredentials;
  if (status === 409) return t.emailTaken;
  if (status === 429) return t.tooMany;
  if (status === 400 && mode === "register") return t.passwordRule;
  return t.genericError;
};

export default function Auth({ api, onLoggedIn }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ email: "", password: "", name: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const set = (field) => (e) => setForm({ ...form, [field]: e.target.value });

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (mode === "register") {
        const reg = await api("post", "/register", { email: form.email, password: form.password, name: form.name });
        if (reg.status !== 201) return setError(errorFor(reg.status, mode));
      }
      const res = await api("post", "/login", { email: form.email, password: form.password });
      if (res.status !== 200) return setError(errorFor(res.status, "login"));
      // A senha de login só fica na memória até o cofre existir (para
      // recusar uma senha de cifragem igual a ela).
      return onLoggedIn({ id: res.body.id, name: res.body.name }, form.password);
    } catch {
      return setError(t.genericError);
    } finally {
      setBusy(false);
    }
  };

  const register = mode === "register";
  return (
    <main className="center">
      <form className="card" onSubmit={submit}>
        <img className="logo" src="/logo-secure-chat.png" alt={t.logoAlt} />
        <h1>{register ? t.registerTitle : t.loginTitle}</h1>
        {register && (
          <label>
            {t.displayName}
            <input value={form.name} onChange={set("name")} maxLength={100} required autoComplete="nickname" />
          </label>
        )}
        <label>
          {t.email}
          <input type="email" value={form.email} onChange={set("email")} required autoComplete="username" />
        </label>
        <label>
          {t.password}
          <input type="password" value={form.password} onChange={set("password")} required minLength={register ? 10 : 1} autoComplete={register ? "new-password" : "current-password"} />
        </label>
        {error && <p className="error" role="alert">{error}</p>}
        <button className="primary" disabled={busy}>{register ? t.registerButton : t.loginButton}</button>
        <button type="button" className="link" onClick={() => { setMode(register ? "login" : "register"); setError(""); }}>
          {register ? t.toLogin : t.toRegister}
        </button>
      </form>
    </main>
  );
}
