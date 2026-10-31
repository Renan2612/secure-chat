#!/usr/bin/env bash
# Provas do frontend (Etapa 5, C4). Sem sudo. Termina com código != 0 se
# qualquer prova falhar.
#
# Uso: scripts/verify-frontend.sh
#      MUTATION=inline-script   scripts/verify-frontend.sh  (deve FALHAR: script inline no index.html)
#      MUTATION=external-script scripts/verify-frontend.sh  (deve FALHAR: <script src="https://..."> no index.html)
#      MUTATION=inner-html      scripts/verify-frontend.sh  (deve FALHAR: innerHTML no código-fonte)
#      MUTATION=unpinned-dep    scripts/verify-frontend.sh  (deve FALHAR: dependência com ^)
#
# Provas:
#   build: npm ci (lockfile) e vite build;
#   dist: nada que o navegador BUSQUE em outro host — src=/href= no HTML,
#     url()/@import no CSS, import/fetch/WebSocket/.src=/.href= no JS (textos
#     de URL soltos, como namespaces XML ou o endereço das mensagens de erro
#     do React, são tolerados: o navegador não os busca, e a CSP barraria);
#     nenhum script inline, style= ou handler on*=; nada de eval nem new
#     Function;
#   src: nada de innerHTML, outerHTML, insertAdjacentHTML, document.write
#     nem dangerouslySetInnerHTML;
#   package.json sem versões com ^ ou ~; lockfile só com registry.npmjs.org;
#   npm audit --omit=dev limpo;
#   proxy no ar: "/" responde 200 com a CSP exata do plano.
# As mutações alteram CÓPIAS e são desfeitas na saída (trap), mesmo em falha.
set -uo pipefail
umask 077
cd "$(dirname "$0")/.."

FE=frontend
HOST="${PUBLIC_HOST:-$(sed -n 's/^PUBLIC_HOST=//p' backend/.env 2>/dev/null | tail -n 1)}"; HOST="${HOST:-localhost}"
BASE="https://$HOST"
MUTATION="${MUTATION:-}"

FAILS=0
ok() { printf '  OK     %s\n' "$*"; }
ko() { printf '  FALHA  %s\n' "$*"; FAILS=$((FAILS + 1)); }
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else ko "$desc"; fi; }
section() { printf '\n== %s\n' "$*"; }

for tool in node npm curl grep sed find; do
  command -v "$tool" >/dev/null || { echo "erro: '$tool' não encontrado" >&2; exit 2; }
done
case "$MUTATION" in
  "" | inline-script | external-script | inner-html | unpinned-dep) ;;
  *) echo "erro: MUTATION inválida: $MUTATION" >&2; exit 2 ;;
esac

TMP="$(mktemp -d)"
MUTANT_SRC="$FE/src/__mutacao__.jsx"
cleanup() {
  local rc=$?
  trap - EXIT INT TERM HUP
  [ -f "$TMP/package.json" ] && cp "$TMP/package.json" "$FE/package.json"
  rm -f "$MUTANT_SRC"
  if [ -n "$MUTATION" ]; then
    if git diff --quiet -- "$FE/package.json" && [ ! -e "$MUTANT_SRC" ]; then
      echo "(mutação desfeita: package.json e src/ como estavam)"
    else
      echo "ERRO: a mutação não foi desfeita; confira $FE/package.json e $MUTANT_SRC" >&2
      rc=3
    fi
  fi
  rm -rf "$TMP"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

section "Preparação"
[ -n "$MUTATION" ] && echo "  (MUTAÇÃO ATIVA: $MUTATION — esperado: provas falharem)"
case "$MUTATION" in
  unpinned-dep)
    cp "$FE/package.json" "$TMP/package.json"
    sed -i 's/"react": "\([0-9]\)/"react": "^\1/' "$FE/package.json"
    check "mutação aplicada (react com ^ no package.json)" grep -q '"react": "\^' "$FE/package.json"
    ;;
  inner-html)
    printf 'export const mutacao = (el, html) => {\n  el.innerHTML = html;\n};\n' >"$MUTANT_SRC"
    check "mutação aplicada ($MUTANT_SRC com innerHTML)" test -f "$MUTANT_SRC"
    ;;
esac

section "Dependências"
check "package.json sem versões com ^ ou ~" bash -c '! grep -E "\"[^\"]+\": \"[~^]" "$0"' "$FE/package.json"
registry_only() {
  local total bad
  total="$(grep -c '"resolved":' "$FE/package-lock.json")"
  bad="$(grep -o '"resolved": "[^"]*' "$FE/package-lock.json" | grep -vc '"resolved": "https://registry.npmjs.org/')"
  echo "         lockfile: $total pacotes, $bad fora de registry.npmjs.org"
  [ "$total" -gt 0 ] && [ "$bad" = 0 ]
}
check "lockfile só com registry.npmjs.org" registry_only
(cd "$FE" && npm audit --omit=dev >"$TMP/audit.txt" 2>&1); AUDIT_RC=$?
check "npm audit --omit=dev: $(tail -n 1 "$TMP/audit.txt")" test "$AUDIT_RC" = 0

section "Build (npm ci + vite build)"
if [ "$MUTATION" = unpinned-dep ]; then
  echo "         (pulado: com o package.json mutado o npm ci recusaria o lockfile)"
else
  (cd "$FE" && npm ci --no-fund --no-audit >"$TMP/ci.txt" 2>&1 && npx vite build >"$TMP/build.txt" 2>&1); BUILD_RC=$?
  check "build concluído" test "$BUILD_RC" = 0
  [ "$BUILD_RC" = 0 ] || sed 's/^/         | /' "$TMP/ci.txt" "$TMP/build.txt" | tail -n 20
fi
DIST="$FE/dist"
case "$MUTATION" in
  inline-script)
    sed -i 's#</head>#<script>document.title="injetado"</script></head>#' "$DIST/index.html"
    check "mutação aplicada (script inline no dist/index.html)" grep -q '<script>document.title' "$DIST/index.html"
    ;;
  external-script)
    sed -i 's#</head>#<script src="https://cdn.malicioso.example/x.js"></script></head>#' "$DIST/index.html"
    check "mutação aplicada (script externo no dist/index.html)" grep -q 'cdn.malicioso.example' "$DIST/index.html"
    ;;
esac

section "dist: nada buscado em outro host, nada inline"
check "dist tem o index.html e os assets" test -s "$DIST/index.html" -a -n "$(find "$DIST/assets" -name '*.js' 2>/dev/null)"
# URL absoluta ("https://", "http://" ou "//host"); os relativos à origem passam.
ABS='(https?:)?//[A-Za-z0-9]'
html_fetch() { grep -oiE "(src|href|action|srcset|poster|data)=[\"']?$ABS[^\"' >]*" "$DIST/index.html"; }
css_fetch() { find "$DIST" -name '*.css' -exec grep -oiE "(url\\([\"']?$ABS[^)\"']*|@import[^;]*)" {} +; }
js_fetch() {
  find "$DIST" -name '*.js' -exec grep -oE \
    "(import\\(?[[:space:]]*[\"'\`]$ABS|from[[:space:]]*[\"'\`]$ABS|fetch\\([[:space:]]*[\"'\`]$ABS|WebSocket\\([[:space:]]*[\"'\`]wss?://|EventSource\\([[:space:]]*[\"'\`]$ABS|sendBeacon\\([[:space:]]*[\"'\`]$ABS|\\.(src|href|action)[[:space:]]*=[[:space:]]*[\"'\`]$ABS|importScripts\\([[:space:]]*[\"'\`]$ABS)[^\"'\`]{0,60}" {} +
}
none() { local out; out="$("$@")"; [ -z "$out" ] || { sed 's/^/         | /' <<<"$out" | head -n 10; return 1; }; }
check "index.html: nenhum src=/href= para outro host" none html_fetch
check "CSS: nenhum url() externo nem @import" none css_fetch
check "JS: nenhum import/fetch/WebSocket/EventSource/.src=/.href= para outro host" none js_fetch
URLS="$(find "$DIST" -name '*.js' -exec grep -ohE 'https?://[A-Za-z0-9.-]+' {} + | sort -u | paste -sd' ')"
echo "         textos de URL no bundle (tolerados, não buscados): ${URLS:-nenhum}"
inline_html() {
  grep -oiE '<script[^>]*>' "$DIST/index.html" | grep -v ' src=' | sed 's/^/         | inline: /'
  grep -oiE '<script[^>]*>[^<]+</script>|[[:space:]](style|on[a-z]+)=[^ >]*|javascript:' "$DIST/index.html" | sed 's/^/         | /'
}
check "index.html: todo <script> tem src; sem style=, on*= nem javascript:" none inline_html
eval_like() { find "$DIST" -name '*.js' -exec grep -ohE '\beval\(|new Function\(' {} +; }
check "JS: sem eval nem new Function" none eval_like

section "src: nada de HTML montado a partir de texto"
html_sinks() { grep -rnE 'innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML' "$FE/src"; }
check "src sem innerHTML, outerHTML, insertAdjacentHTML, document.write nem dangerouslySetInnerHTML" none html_sinks

section "Proxy no ar: CSP servida"
CA="$TMP/ca.crt"
if scripts/export-ca.sh "$CA" >/dev/null 2>&1; then
  curl -s -D "$TMP/h_root" -o /dev/null --cacert "$CA" "$BASE/"; status="$(awk 'NR==1{print $2}' "$TMP/h_root" 2>/dev/null)"
  check "$BASE/ responde 200" test "$status" = 200
  CSP_EXPECTED="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' wss://$HOST; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
  csp="$(grep -i '^content-security-policy:' "$TMP/h_root" | head -n 1 | sed -E 's/^[^:]+: *//' | tr -d '\r')"
  check "CSP servida = a do plano" test "$csp" = "$CSP_EXPECTED"
else
  ko "não foi possível exportar a CA (a stack está no ar? docker compose --env-file backend/.env up --build -d)"
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "RESULTADO: todas as provas passaram"; else echo "RESULTADO: $FAILS prova(s) falharam"; fi
[ "$FAILS" -eq 0 ]
