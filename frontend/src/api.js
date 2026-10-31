// API HTTP na MESMA origem (/api), com o cookie de sessão (B-D3). O
// navegador manda o Origin sozinho; o servidor confere (CSRF). Não segue
// redirecionamentos e não usa cache.
export const createApi = (base = "/api", fetchImpl = (...args) => globalThis.fetch(...args)) => async (method, path, body) => {
  const res = await fetchImpl(`${base}${path}`, {
    method: method.toUpperCase(),
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }
  return { status: res.status, body: parsed };
};
