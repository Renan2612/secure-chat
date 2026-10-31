// Paridade do núcleo E2EE no frontend (B-D2): o MESMO shared/e2ee, via alias
// do Vite, tem de dar os mesmos resultados que no Node, byte a byte.
//  - vetores independentes (OpenSSL + Python) de fingerprint e número de
//    segurança: os de backend/tests/e2ee/vectors.test.js;
//  - vetores produzidos pelo NODE (tests/fixtures/node-vectors.json, dados
//    fictícios): um envelope v2, um nome de sala assinado e um cofre selado,
//    que o lado do navegador precisa abrir;
//  - ida e volta pelo adaptador de navegador (src/crypto/browser.js).
import { describe, expect, test } from "vitest";
import e2ee from "../src/crypto/e2ee.js";
import { importRoomKey } from "../src/crypto/browser.js";
import vectors from "./fixtures/node-vectors.json";

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

describe("vetores independentes (OpenSSL + Python)", () => {
  test("fingerprint", async () => {
    expect(await e2ee.fingerprint(A)).toBe("67233c8d6cc55d87428d1393cd3dbc44a57a6910ca661aad3b89afda050b1d5a");
    expect(await e2ee.fingerprint(B)).toBe("ee9526779858e05e5b33bdd318f5faebfffd1d3a36f8e06e22f860c9266f869d");
  });

  test("número de segurança, nos dois sentidos, 12 grupos de 5 dígitos", async () => {
    const expected = "38249 81457 60660 17292 72930 01302 35015 15685 89914 65352 59675 19715";
    expect(await e2ee.safetyNumber(A, B)).toBe(expected);
    expect(await e2ee.safetyNumber(B, A)).toBe(expected);
  });
});

describe("vetores produzidos pelo Node", () => {
  const roomKeys = async () => ({ 1: await importRoomKey(vectors.rawRoomKey) });

  test("o navegador decifra e verifica o envelope v2 do Node", async () => {
    const text = await e2ee.decryptMessage({ body: vectors.body, roomKeys: await roomKeys(), roomId: 7, senderId: 3, cid: "vetor-1", senderEcdsaPub: vectors.ecdsaPub });
    expect(text).toBe("olá, vetor ✓");
  });

  test("o navegador abre o nome de sala assinado pelo Node (assinatura conferida)", async () => {
    const r = await e2ee.openRoomName({ nameEnv: vectors.nameEnv, roomKeys: await roomKeys(), roomId: 7, ownerId: 3, ownerEcdsaPub: vectors.ecdsaPub, last: null });
    expect(r).toMatchObject({ name: "Sala do vetor", verified: true, remember: { seq: 2, ownerId: 3 } });
  });

  test("o navegador abre o cofre selado pelo Node (mesmo formato do keystore.js)", async () => {
    expect(await e2ee.openJson("senha-de-cifragem-do-vetor", vectors.sealed)).toEqual({ vetor: "cofre", n: 1 });
    await expect(e2ee.openJson("senha-errada-123", vectors.sealed)).rejects.toMatchObject({ code: "BAD_PASSPHRASE" });
  });

  test("adulterar o vetor do Node é detectado no navegador", async () => {
    const env = JSON.parse(vectors.body);
    const flipped = JSON.stringify({ ...env, cid: undefined, kv: 1, ct: env.ct.replace(/^./, (c) => (c === "A" ? "B" : "A")) });
    await expect(e2ee.decryptMessage({ body: flipped, roomKeys: await roomKeys(), roomId: 7, senderId: 3, cid: "vetor-1", senderEcdsaPub: vectors.ecdsaPub })).rejects.toThrow();
  });
});

describe("ida e volta no navegador", () => {
  test("cifrar e decifrar uma mensagem; a chave importada pelo adaptador funciona com o núcleo", async () => {
    const id = await e2ee.generateIdentity();
    const pub = await e2ee.exportPublicKeys(id);
    const roomKey = await importRoomKey(vectors.rawRoomKey);
    const body = await e2ee.encryptMessage({ roomKey, kv: 1, roomId: 9, senderId: 1, cid: "c", text: "oi", senderEcdsaKey: id.ecdsa.privateKey, exp: e2ee.expFor(60) });
    expect(await e2ee.decryptMessage({ body, roomKeys: { 1: roomKey }, roomId: 9, senderId: 1, cid: "c", senderEcdsaPub: pub.ecdsaPub })).toBe("oi");
  });
});
