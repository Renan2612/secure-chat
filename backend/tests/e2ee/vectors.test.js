// P3 (pendência da 4b-1): vetores FIXOS de fingerprint e número de
// segurança, calculados por ferramentas independentes do código do projeto
// (OpenSSL para as chaves, Python/hashlib para os valores). Um frontend
// futuro tem de bater com estes valores byte a byte.
//
// Reprodução (fora do repositório):
//   for k in a_ecdh a_ecdsa b_ecdh b_ecdsa; do
//     openssl ecparam -name prime256v1 -genkey -noout -out $k.pem
//     openssl ec -in $k.pem -pubout -outform DER -out $k.der
//   done
//   python3 -I - <<'PY'
//   import base64, hashlib, json
//   b = lambda f: base64.urlsafe_b64encode(open(f, "rb").read()).decode().rstrip("=")
//   A = {"userId": 7, "ecdhPub": b("a_ecdh.der"), "ecdsaPub": b("a_ecdsa.der")}
//   B = {"userId": 3, "ecdhPub": b("b_ecdh.der"), "ecdsaPub": b("b_ecdsa.der")}
//   canon = lambda items: json.dumps(items, separators=(",", ":")).encode()
//   fp = lambda u: hashlib.sha256(canon(["secure-chat/v1/fingerprint", u["ecdsaPub"], u["ecdhPub"]])).hexdigest()
//   lo, hi = sorted([A, B], key=lambda u: u["userId"])
//   d = hashlib.sha256(canon(["secure-chat/v1/safety", lo["userId"], lo["ecdsaPub"], lo["ecdhPub"],
//                             hi["userId"], hi["ecdsaPub"], hi["ecdhPub"]])).digest()
//   n = int.from_bytes(d, "big")
//   print(fp(A), fp(B), " ".join("%05d" % (((n >> (256 - 20 * (i + 1))) & 0xFFFFF) % 100000) for i in range(12)))
//   PY
// As chaves abaixo são as que saíram dessa receita (só as PÚBLICAS; as
// privadas foram descartadas).
const e2ee = require("../../../shared/e2ee");
const { fingerprint: serverFingerprint, isP256Spki } = require("../../helpers/publicKeys");

const A = {
  userId: 7,
  ecdhPub: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKq7F18zfMshVZO241DUvVtmWW0cSaIQMZIcAuMb68v5SG8l_K2wFqniq2B-8PNB3wG00_PHe8ezc7xwYZz-5zA",
  ecdsaPub: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE-febeXkr5pZxV3JdpMK8DArkFsPAnNI4DlN1OZ14UVSAj-KBeyRmDWMeLc8gGxutqEAML2Jdnk4vGNuFNzjrPw",
};
const B = {
  userId: 3,
  ecdhPub: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7Ahb2dUq-aQgknUmEJqFMBXfIPZ_vcKzolm8ukaetVXwrw3coAMJZIMou87eQWuxtxqeCVHxYAjyrpJjZyyATA",
  ecdsaPub: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECog1jy5XAV9YrEEvMTotnlt39yEr8MyieyFlOdmKp6kA93yCPSMKQXyaKgDZtLd_Dm5X0tM1V4k1C6A7iWVOtQ",
};
const FP_A = "67233c8d6cc55d87428d1393cd3dbc44a57a6910ca661aad3b89afda050b1d5a";
const FP_B = "ee9526779858e05e5b33bdd318f5faebfffd1d3a36f8e06e22f860c9266f869d";
const SAFETY = "38249 81457 60660 17292 72930 01302 35015 15685 89914 65352 59675 19715";

test("as chaves do vetor são SPKI P-256 válidas", () => {
  for (const key of [A.ecdhPub, A.ecdsaPub, B.ecdhPub, B.ecdsaPub]) expect(isP256Spki(key)).toBe(true);
});

test("fingerprint (cliente e servidor) = vetor calculado em Python", async () => {
  expect(await e2ee.fingerprint(A)).toBe(FP_A);
  expect(await e2ee.fingerprint(B)).toBe(FP_B);
  expect(serverFingerprint(A)).toBe(FP_A);
  expect(serverFingerprint(B)).toBe(FP_B);
});

test("número de segurança = vetor calculado em Python, nos dois sentidos", async () => {
  expect(await e2ee.safetyNumber(A, B)).toBe(SAFETY);
  expect(await e2ee.safetyNumber(B, A)).toBe(SAFETY);
});

test("trocar ecdh e ecdsa de lugar muda a fingerprint (a ordem faz parte do formato)", async () => {
  expect(await e2ee.fingerprint({ ecdhPub: A.ecdsaPub, ecdsaPub: A.ecdhPub })).not.toBe(FP_A);
});
