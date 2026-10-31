// Ataques da Etapa 6 (parte HTTP/WebSocket), rodados contra DUAS stacks
// LOCAIS do próprio projeto: o original (esperado: vulnerável) e a final
// (esperado: bloqueado). Lê a configuração dos alvos do stdin (JSON) e
// imprime no stdout um JSON com um resultado por (ataque, alvo). NÃO decide
// o código de saída do processo — quem assere e falha é o attack-matrix.sh.
//
// Trava de segurança (regra da etapa, também no lib-local-guard.sh): só
// mira 127.0.0.1/localhost; qualquer alvo não-local aborta antes de atacar.
import { io } from "socket.io-client";
import { WebSocket } from "ws";
import { readFileSync } from "node:fs";
import { request, asJson, Jar } from "./lib/net.js";

const hostOf = (v) => {
  let h = String(v).replace(/^[a-z]+:\/\//i, "");
  h = h.split("/")[0].split("?")[0];
  h = h.includes("@") ? h.slice(h.indexOf("@") + 1) : h;
  return h.replace(/:\d+$/, "");
};
const isLocal = (v) => ["127.0.0.1", "localhost", "[::1]", "::1"].includes(hostOf(v));

const cfg = JSON.parse(await readStdin());
for (const url of [cfg.original?.api, cfg.final?.api, cfg.final?.ws].filter(Boolean)) {
  if (!isLocal(url)) {
    process.stderr.write(`ABORTADO: alvo não-local recusado: ${url}\n`);
    process.exit(3);
  }
}

function readStdin() {
  return new Promise((resolve) => {
    let d = "";
    process.stdin.on("data", (c) => (d += c));
    process.stdin.on("end", () => resolve(d || "{}"));
  });
}

const results = [];
const add = (r) => results.push(r);
// vulneravel=true → o ataque funcionou. ok = observado bate com o esperado.
const record = (id, titulo, alvo, esperaVuln, vulneravel, controle, detalhe) => {
  const esperado = esperaVuln ? "vulneravel" : "bloqueado";
  const observado = vulneravel === null ? "inconclusivo" : vulneravel ? "vulneravel" : "bloqueado";
  add({ id, titulo, alvo, esperado, observado, ok: observado === esperado, controle, detalhe });
};

const MT = 5000;

// Prepara um usuário logado no ORIGINAL (register nunca responde — bug do
// original —, então dispara e espera o usuário aparecer via checkUserExists).
const prepOriginal = async (api, tag) => {
  const email = `atk-${tag}-${Date.now()}@example.invalid`;
  const password = "senha-de-ataque";
  await request("POST", `${api}/register`, { body: { email, password, name: tag }, timeoutMs: 2000 });
  let id = null;
  for (let i = 0; i < 20 && id === null; i += 1) {
    const r = await request("POST", `${api}/checkUserExists`, { body: { email }, timeoutMs: 2000 });
    const rows = asJson(r) ?? [];
    if (rows.length >= 1) id = rows[rows.length - 1].id;
    else await new Promise((s) => setTimeout(s, 200));
  }
  const jar = new Jar();
  await request("POST", `${api}/login`, { body: { email, password }, jar, timeoutMs: 3000 });
  return { email, password, id, jar };
};

// Usuário logado na FINAL (register/login com o Origin da própria origem).
const prepFinal = async (api, origin, caPath, tag) => {
  const email = `atk-${tag}-${Date.now()}@example.invalid`;
  const password = "senha-de-ataque-1234";
  const headers = { Origin: origin };
  await request("POST", `${api}/register`, { headers, body: { email, password, name: tag }, caPath, timeoutMs: MT });
  const jar = new Jar();
  const login = await request("POST", `${api}/login`, { headers, body: { email, password }, jar, caPath, timeoutMs: MT });
  const me = asJson(login);
  return { email, password, id: me?.id ?? null, jar, setCookies: login.setCookies };
};

const flags = (setCookies, name) => {
  const line = (setCookies ?? []).find((c) => c.startsWith(`${name}=`)) ?? "";
  const has = (f) => new RegExp(`;\\s*${f}`, "i").test(line);
  const sameSite = /;\s*SameSite=([^;]+)/i.exec(line)?.[1] ?? null;
  return { present: Boolean(line), secure: has("Secure"), httpOnly: has("HttpOnly"), sameSite };
};

// --- socket.io (original) e ws (final) com timeout e limpeza --------------
const socketIoReceives = (api, { origin } = {}) =>
  new Promise((resolve) => {
    const opts = { transports: ["websocket"], reconnection: false, timeout: 3000, forceNew: true };
    if (origin) opts.extraHeaders = { Origin: origin };
    const listener = io(api, opts);
    const sender = io(api, { transports: ["websocket"], reconnection: false, timeout: 3000, forceNew: true });
    let done = false;
    const finish = (v) => { if (!done) { done = true; try { listener.close(); sender.close(); } catch {} resolve(v); } };
    const timer = setTimeout(() => finish({ received: false, reason: "timeout" }), 6000);
    listener.on("receive_message", (d) => { clearTimeout(timer); finish({ received: true, data: d }); });
    listener.on("connect_error", (e) => { clearTimeout(timer); finish({ received: false, reason: `connect_error:${e.message}` }); });
    listener.on("connect", () => sender.on("connect", () => setTimeout(() => sender.emit("send_message", { marker: "SNIFF-SOCKET" }), 150)));
  });

const wsUpgrade = (url, { cookie, origin, caPath } = {}) =>
  new Promise((resolve) => {
    const headers = {};
    if (cookie) headers.Cookie = cookie;
    const opts = { headers, rejectUnauthorized: Boolean(caPath), ...(caPath ? { ca: readFileSyncSafe(caPath) } : {}) };
    if (origin) opts.origin = origin;
    const ws = new WebSocket(url, opts);
    let done = false;
    const finish = (v) => { if (!done) { done = true; try { ws.terminate(); } catch {} resolve(v); } };
    const timer = setTimeout(() => finish({ open: false, status: 0, reason: "timeout" }), 6000);
    ws.on("open", () => { clearTimeout(timer); finish({ open: true }); });
    ws.on("unexpected-response", (_req, res) => { clearTimeout(timer); finish({ open: false, status: res.statusCode }); });
    ws.on("error", (err) => { clearTimeout(timer); finish({ open: false, status: 0, reason: err.message }); });
  });

function readFileSyncSafe(p) { try { return readFileSync(p); } catch { return undefined; } }

// =========================== ORIGINAL =====================================
if (cfg.original?.api) {
  const api = cfg.original.api;
  const a = await prepOriginal(api, "a");

  // 2. Falsificar identidade: POST /session grava qualquer userId.
  {
    const jar = new Jar();
    await request("POST", `${api}/session`, { body: { userId: 424242 }, jar, timeoutMs: MT });
    const sess = asJson(await request("GET", `${api}/session`, { jar, timeoutMs: MT }));
    const vuln = sess?.id === 424242;
    record(2, "Falsificar identidade (sessão / remetente)", "original", true, vuln,
      "POST /session grava um userId arbitrário e GET /session o reflete", `GET /session => ${JSON.stringify(sess)}`);
  }

  // 3. Ler sala alheia: A cria sala, forja uma mensagem, e um ANÔNIMO lê.
  {
    const room = asJson(await request("POST", `${api}/createRoom`, { body: { name: "sala-alvo" }, jar: a.jar, timeoutMs: MT }));
    const roomId = Array.isArray(room) ? room[0]?.id : room?.id;
    const marker = `SEGREDO-ORIG-${Date.now()}`;
    if (roomId && a.id) {
      await request("POST", `${api}/messages`, { body: { room: { id: roomId }, user: { id: a.id }, message: marker }, timeoutMs: MT });
    }
    const anon = asJson(await request("GET", `${api}/messages/${roomId}`, { timeoutMs: MT })) ?? [];
    const users = asJson(await request("GET", `${api}/roomUsers/${roomId}`, { timeoutMs: MT })) ?? [];
    const vuln = anon.some((m) => (m.message || "").includes(marker));
    record(3, "Ler sala alheia sem ser membro", "original", true, vuln,
      "GET /messages/:id (sem sessão) devolve o texto da mensagem", `mensagens lidas=${anon.length}, membros expostos=${users.length}`);
  }

  // 4. Ouvinte anônimo no socket recebe broadcast de qualquer sala.
  {
    const r = await socketIoReceives(api);
    record(4, "Ouvinte anônimo no WebSocket", "original", true, r.received,
      "socket.io sem login recebe o broadcast receive_message", `recebido=${r.received}${r.reason ? ` (${r.reason})` : ""}`);
  }

  // 5. Vazamento de hash via checkUserExists.
  {
    const rows = asJson(await request("POST", `${api}/checkUserExists`, { body: { email: a.email }, timeoutMs: MT })) ?? [];
    const vuln = rows.some((u) => /^\$2[aby]\$/.test(u.password || ""));
    record(5, "Vazamento do hash de senha", "original", true, vuln,
      "checkUserExists devolve a coluna password (hash bcrypt)", `linhas=${rows.length}, traz_campo_password=${vuln}`);
  }

  // 6. Entrar em sala sem a chave de convite.
  {
    const room = asJson(await request("POST", `${api}/createRoom`, { body: { name: "sala-convite" }, jar: a.jar, timeoutMs: MT }));
    const roomId = Array.isArray(room) ? room[0]?.id : room?.id;
    const b = await prepOriginal(api, "b");
    const joined = await request("POST", `${api}/joinRooms`, { body: { idRoom: roomId }, jar: b.jar, timeoutMs: MT });
    const rows = asJson(joined) ?? [];
    const vuln = joined.status === 200 && rows.length >= 1;
    record(6, "Entrar em sala sem a chave de convite", "original", true, vuln,
      "joinRooms aceita idRoom sem conferir chave nenhuma", `status=${joined.status}, vinculo_criado=${rows.length >= 1}`);
  }

  // 8a. CSRF: POST com Origin de outro site ainda é processado.
  {
    const r = await request("POST", `${api}/checkUserExists`, { headers: { Origin: "https://evil.example" }, body: { email: a.email }, timeoutMs: MT });
    const vuln = r.status === 200 && (asJson(r) ?? []).length >= 1;
    record("8a", "CSRF (POST com Origin de outro site)", "original", true, vuln,
      "nenhuma checagem de Origin: a requisição de outro site responde", `status=${r.status}`);
  }

  // 8b. CSWSH: socket cross-origin anônimo recebe mensagens.
  {
    const r = await socketIoReceives(api, { origin: "https://evil.example" });
    record("8b", "CSWSH (WebSocket com Origin de outro site)", "original", true, r.received,
      "o handshake do socket.io não bloqueia Origin de outro site", `recebido=${r.received}${r.reason ? ` (${r.reason})` : ""}`);
  }

  // 9. Força bruta de login: 30 tentativas, nenhuma barrada por 429.
  {
    const tries = await Promise.all(
      Array.from({ length: 30 }, () => request("POST", `${api}/login`, { body: { email: a.email, password: "errada" }, timeoutMs: 1500 }))
    );
    const got429 = tries.filter((t) => t.status === 429).length;
    record(9, "Força bruta de login (sem limite)", "original", true, got429 === 0,
      "30 tentativas e nenhum 429: não há rate limit", `tentativas=30, respostas_429=${got429}`);
  }

  // 10. Flags do cookie de sessão.
  {
    const jar = new Jar();
    const login = await request("POST", `${api}/login`, { body: { email: a.email, password: a.password }, jar, timeoutMs: MT });
    const f = flags(login.setCookies, "session");
    const vuln = f.present && (!f.secure || !f.sameSite);
    record(10, "Flags do cookie de sessão", "original", true, vuln,
      "cookie de sessão sem Secure e sem SameSite", `present=${f.present} secure=${f.secure} httpOnly=${f.httpOnly} sameSite=${f.sameSite}`);
  }

  // 11h. Cabeçalhos de segurança (HSTS/CSP) ausentes.
  {
    const r = await request("GET", `${api}/rooms`, { timeoutMs: MT });
    const hsts = Boolean(r.headers["strict-transport-security"]);
    const csp = Boolean(r.headers["content-security-policy"]);
    record("11h", "Cabeçalhos HSTS e CSP", "original", true, !hsts && !csp,
      "resposta sem HSTS e sem CSP", `hsts=${hsts} csp=${csp}`);
  }
}

// ============================= FINAL ======================================
if (cfg.final?.api) {
  const { api, ws, caPath, origin } = cfg.final;
  const evil = "https://evil.example";
  const a = await prepFinal(api, origin, caPath, "a");
  const b = await prepFinal(api, origin, caPath, "b");

  // 2. Rotas de falsificação de identidade não existem mais.
  {
    const s1 = await request("POST", `${api}/session`, { headers: { Origin: origin }, body: { userId: 1 }, caPath, jar: a.jar, timeoutMs: MT });
    const s2 = await request("GET", `${api}/session`, { caPath, jar: a.jar, timeoutMs: MT });
    const s3 = await request("POST", `${api}/messages`, { headers: { Origin: origin }, body: { room: { id: 1 }, user: { id: 1 }, message: "x" }, caPath, jar: a.jar, timeoutMs: MT });
    const blocked = [s1.status, s2.status, s3.status].every((s) => s === 404 || s === 401);
    record(2, "Falsificar identidade (sessão / remetente)", "final", false, !blocked,
      "POST/GET /session e POST /messages foram removidos; o remetente do MSG_SEND vem da sessão (backend/tests/ws)",
      `POST /session=${s1.status}, GET /session=${s2.status}, POST /messages=${s3.status}`);
  }

  // 3. Ler sala alheia: B cria a sala; A (não-membro) é barrado; B (membro) lê.
  {
    const created = asJson(await request("POST", `${api}/createRoom`, { headers: { Origin: origin }, body: {}, caPath, jar: b.jar, timeoutMs: MT }));
    const roomId = created?.id;
    const msgA = await request("GET", `${api}/messages/${roomId}`, { caPath, jar: a.jar, timeoutMs: MT });
    const usersA = await request("GET", `${api}/roomUsers/${roomId}`, { caPath, jar: a.jar, timeoutMs: MT });
    const msgB = await request("GET", `${api}/messages/${roomId}`, { caPath, jar: b.jar, timeoutMs: MT });
    const blocked = msgA.status === 403 && usersA.status === 403;
    record(3, "Ler sala alheia sem ser membro", "final", false, !blocked,
      `controle positivo: o dono (membro) lê a própria sala (status ${msgB.status})`,
      `não-membro GET /messages=${msgA.status}, GET /roomUsers=${usersA.status}`);
  }

  // 4. Upgrade do /ws sem sessão é recusado; com sessão, abre (controle +).
  {
    const anon = await wsUpgrade(ws, { origin, caPath }); // Origin válido, sem cookie → cai na checagem de sessão (401)
    const authed = await wsUpgrade(ws, { cookie: a.jar.header(), origin, caPath });
    record(4, "Ouvinte anônimo no WebSocket", "final", false, anon.open,
      `controle positivo: com sessão o upgrade abre (open=${authed.open})`,
      `sem sessão (Origin válido): open=${anon.open}, status=${anon.status}`);
  }

  // 5. checkUserExists removido.
  {
    const r = await request("POST", `${api}/checkUserExists`, { headers: { Origin: origin }, body: { email: a.email }, caPath, jar: a.jar, timeoutMs: MT });
    record(5, "Vazamento do hash de senha", "final", false, r.status !== 404,
      "a rota checkUserExists foi removida (404)", `status=${r.status}`);
  }

  // 6. joinRooms exige a chave de convite.
  {
    const created = asJson(await request("POST", `${api}/createRoom`, { headers: { Origin: origin }, body: {}, caPath, jar: b.jar, timeoutMs: MT }));
    const roomId = created?.id;
    const wrong = await request("POST", `${api}/joinRooms`, { headers: { Origin: origin }, body: { idRoom: roomId, key: "chave-errada" }, caPath, jar: a.jar, timeoutMs: MT });
    record(6, "Entrar em sala sem a chave de convite", "final", false, wrong.status === 200,
      "convite inválido é recusado (403, resposta genérica)", `status=${wrong.status}`);
  }

  // 8a. CSRF: POST com Origin de outro site é recusado (415/403).
  {
    const r = await request("POST", `${api}/login`, { headers: { Origin: evil }, body: { email: a.email, password: a.password }, caPath, timeoutMs: MT });
    const ok = await request("POST", `${api}/login`, { headers: { Origin: origin }, body: { email: a.email, password: a.password }, caPath, jar: new Jar(), timeoutMs: MT });
    record("8a", "CSRF (POST com Origin de outro site)", "final", false, r.status < 400,
      `controle positivo: com o Origin certo o login responde ${ok.status}`, `login com Origin de outro site => ${r.status}`);
  }

  // 8b. CSWSH: /ws com Origin de outro site é recusado mesmo com sessão.
  {
    const r = await wsUpgrade(ws, { cookie: a.jar.header(), origin: evil, caPath });
    record("8b", "CSWSH (WebSocket com Origin de outro site)", "final", false, r.open,
      "o upgrade confere o Origin antes da sessão", `open=${r.open}, status=${r.status}`);
  }

  // 9. Força bruta: aparece 429 (feita por ÚLTIMO: gasta o limite por IP).
  {
    let seen = 0;
    let attempts = 0;
    for (; attempts < 30 && seen === 0; attempts += 1) {
      const r = await request("POST", `${api}/login`, { headers: { Origin: origin }, body: { email: a.email, password: "errada" }, caPath, timeoutMs: MT });
      if (r.status === 429) seen = attempts + 1;
    }
    record(9, "Força bruta de login (com limite)", "final", false, seen === 0,
      "o rate limit responde 429 (controle positivo do limitador)", `429 na tentativa ${seen || "nenhuma"} de ${attempts}`);
  }

  // 10. Flags do cookie de sessão (sid).
  {
    const f = flags(a.setCookies, "sid");
    const blocked = f.present && f.secure && f.httpOnly && Boolean(f.sameSite);
    record(10, "Flags do cookie de sessão", "final", false, !blocked,
      "sid com Secure, HttpOnly e SameSite", `present=${f.present} secure=${f.secure} httpOnly=${f.httpOnly} sameSite=${f.sameSite}`);
  }

  // 11h. HSTS e CSP presentes.
  {
    const r = await request("GET", `${origin}/`, { caPath, timeoutMs: MT });
    const hsts = Boolean(r.headers["strict-transport-security"]);
    const csp = Boolean(r.headers["content-security-policy"]);
    record("11h", "Cabeçalhos HSTS e CSP", "final", false, !(hsts && csp),
      "a origem serve HSTS e CSP", `hsts=${hsts} csp=${csp}`);
  }
}

process.stdout.write(JSON.stringify(results, null, 2));
process.exit(0);
