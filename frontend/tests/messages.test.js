// Redutor das mensagens de uma sala (B4), puro. Estados: sending,
// confirmed, failed, ok (recebida e verificada), invalid ("mensagem
// inválida", sem conteúdo), no_key, untrusted. Deduplicação por
// (remetente, cid); ordem pelo id do servidor; expiradas saem da memória.
import { describe, expect, test } from "vitest";
import { messagesReducer, initialMessages } from "../src/chat/messages.js";

const ME = 1;
const run = (actions, state = initialMessages) => actions.reduce(messagesReducer, state);
const ok = (over = {}) => ({ type: "received", me: ME, packet: { id: 10, from: 2, cid: "b1", ts: "t", ...over.packet }, result: { status: "ok", text: "oi", verified: false, exp: null, ...over.result } });

describe("envio próprio", () => {
  test("sending → confirmed com o ACK; a própria entrega depois não duplica", () => {
    const s = run([
      { type: "sent", me: ME, cid: "c1", text: "olá", exp: null },
      { type: "acked", me: ME, cid: "c1", id: 11, ts: "t1" },
      ok({ packet: { id: 11, from: ME, cid: "c1" }, result: { text: "olá" } }),
    ]);
    expect(s.items).toEqual([expect.objectContaining({ key: "1:c1", status: "confirmed", id: 11, text: "olá", mine: true })]);
  });

  test("falhou: fica marcado (o texto continua, para reenviar)", () => {
    const s = run([{ type: "sent", me: ME, cid: "c1", text: "olá", exp: null }, { type: "failed", me: ME, cid: "c1", code: "TIMEOUT" }]);
    expect(s.items[0]).toMatchObject({ status: "failed", reason: "TIMEOUT", text: "olá" });
  });
});

describe("recebidas", () => {
  test("ok: texto e selo de verificação; duplicata é ignorada", () => {
    const s = run([ok(), { ...ok(), result: { status: "duplicate" } }]);
    expect(s.items).toHaveLength(1);
    expect(s.items[0]).toMatchObject({ key: "2:b1", status: "ok", text: "oi", verified: false });
  });

  test("ATAQUE: inválida nunca carrega texto; a legítima com o mesmo (remetente, cid) a substitui", () => {
    const s1 = run([{ ...ok(), result: { status: "invalid", reason: "INVALID_MESSAGE", text: "não pode aparecer" } }]);
    expect(s1.items[0]).toEqual(expect.objectContaining({ status: "invalid" }));
    expect(s1.items[0].text).toBeUndefined();
    const s2 = run([ok()], s1);
    expect(s2.items).toHaveLength(1);
    expect(s2.items[0]).toMatchObject({ status: "ok", text: "oi" });
  });

  test("ATAQUE: inválida com o cid de uma já aceita não a apaga nem a troca", () => {
    const s = run([ok(), { ...ok(), result: { status: "invalid" } }]);
    expect(s.items).toEqual([expect.objectContaining({ status: "ok", text: "oi" })]);
  });

  test("sem chave e remetente não confiável: marcadores, sem texto", () => {
    const s = run([
      { ...ok({ packet: { id: 3, cid: "x" } }), result: { status: "missing_key", kv: 2 } },
      { ...ok({ packet: { id: 4, cid: "y" } }), result: { status: "untrusted", trust: "changed" } },
    ]);
    expect(s.items.map((i) => [i.status, i.text])).toEqual([["no_key", undefined], ["untrusted", undefined]]);
  });

  test("vencida ao chegar: não entra", () => {
    expect(run([{ ...ok(), result: { status: "expired" } }]).items).toEqual([]);
  });

  test("ordem pelo id do servidor (histórico chega fora de ordem); pendentes no fim", () => {
    const s = run([
      { type: "sent", me: ME, cid: "p", text: "pendente", exp: null },
      ok({ packet: { id: 30, cid: "c30" } }),
      ok({ packet: { id: 10, cid: "c10" } }),
      ok({ packet: { id: 20, cid: "c20" } }),
    ]);
    expect(s.items.map((i) => i.id ?? "p")).toEqual([10, 20, 30, "p"]);
  });
});

describe("expiração e limpeza", () => {
  test("ao vencer, sai da memória (inclusive o texto)", () => {
    const s = run([ok({ result: { exp: 100 } }), ok({ packet: { id: 11, cid: "b2" } }), { type: "expire", nowMs: 100_000 }]);
    expect(s.items.map((i) => i.cid)).toEqual(["b2"]);
    expect(JSON.stringify(s)).not.toContain('"oi","verified":false,"exp":100');
  });

  test("reset (bloqueio do cofre, logout, troca de sala) apaga tudo", () => {
    expect(run([ok(), { type: "reset" }])).toEqual(initialMessages);
  });
});
