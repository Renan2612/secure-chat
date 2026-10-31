// Ponta a ponta no navegador (C5): Alice e Bob em contextos SEPARADOS (cada
// um com o próprio IndexedDB, como dois navegadores), contra a stack real.
import { expect, test } from "@playwright/test";

const STAMP = `${Date.now()}`;
const LOGIN = "senha-de-login-e2e-123";
const PASS = "senha-de-cifragem-e2e-456";
const ROOM = `Sala E2E ${STAMP}`;
const XSS = '<img src=x onerror="document.title=\'XSS\'">';

const watch = (page, bag) => {
  page.on("console", (m) => bag.push(m.text()));
  page.on("pageerror", (e) => bag.push(`pageerror: ${e.message}`));
  page.on("dialog", (d) => (d.type() === "confirm" ? d.accept() : d.dismiss()));
};

const signUp = async (page, who) => {
  await page.goto("/");
  await page.getByText("Não tem conta? Criar uma").click();
  await page.getByLabel("Nome de exibição").fill(who);
  await page.getByLabel("E-mail").fill(`e2e-${STAMP}-${who.toLowerCase()}@example.invalid`);
  await page.getByLabel("Senha de login").fill(LOGIN);
  await page.getByRole("button", { name: "Criar conta" }).click();
  // ATAQUE (acréscimo b): senha de cifragem igual à de login é recusada.
  await page.getByLabel("Senha de cifragem", { exact: true }).fill(LOGIN);
  await page.getByLabel("Repita a senha de cifragem").fill(LOGIN);
  await page.getByLabel("Entendi que não há recuperação").check();
  await page.getByRole("button", { name: "Criar cofre" }).click();
  await expect(page.getByText("A senha de cifragem precisa ser diferente da senha de login.")).toBeVisible();
  await page.getByLabel("Senha de cifragem", { exact: true }).fill(PASS);
  await page.getByLabel("Repita a senha de cifragem").fill(PASS);
  await page.getByRole("button", { name: "Criar cofre" }).click();
  await expect(page.getByRole("button", { name: "Criar sala" })).toBeVisible({ timeout: 20000 });
};

test("fluxo completo com dois navegadores: sala, aprovação, mensagens, verificação, efêmera, remoção, celular", async ({ browser }) => {
  const logs = { alice: [], bob: [] };
  const aliceCtx = await browser.newContext();
  const bobCtx = await browser.newContext();
  const alice = await aliceCtx.newPage();
  const bob = await bobCtx.newPage();
  watch(alice, logs.alice);
  watch(bob, logs.bob);
  // Relógio controlável só na página do Bob (corre normalmente até ser
  // adiantado): prova que a efêmera SAI da tela ao vencer.
  await bob.clock.install();

  await signUp(alice, "Alice");
  await signUp(bob, "Bob");

  // Alice cria a sala; o limite de 100 bytes aparece ao digitar.
  await alice.getByRole("button", { name: "Criar sala" }).click();
  await alice.getByLabel("Nome da sala").fill("é".repeat(51));
  await expect(alice.getByText("O nome passa de 100 bytes.")).toBeVisible();
  await expect(alice.getByRole("button", { name: "Criar", exact: true })).toBeDisabled();
  await alice.getByLabel("Nome da sala").fill(ROOM);
  await expect(alice.getByText(`${new TextEncoder().encode(ROOM).length}/100 bytes`)).toBeVisible();
  await alice.getByRole("button", { name: "Criar", exact: true }).click();
  await expect(alice.locator(".invite code")).toHaveCount(2, { timeout: 15000 });
  const codes = await alice.locator(".invite code").allInnerTexts();
  const [roomId, invite] = codes;
  expect(invite).toMatch(/^[0-9a-f]{32}$/);
  await alice.getByRole("button", { name: "Pronto" }).click();
  await expect(alice.getByRole("heading", { name: ROOM })).toBeVisible();
  await expect(alice.locator(".invite")).toHaveCount(0); // o convite sumiu da tela

  // Bob entra: sem a chave até a Alice entregar (ele não foi verificado).
  await bob.getByRole("button", { name: "Entrar com convite" }).click();
  await bob.getByLabel("ID da sala").fill(roomId);
  await bob.getByLabel("Convite").fill(invite);
  await bob.getByRole("button", { name: "Entrar", exact: true }).click();
  await expect(bob.getByText("Aguardando a chave da sala")).toBeVisible({ timeout: 15000 });
  await expect(bob.getByRole("heading", { name: `Sala #${roomId} (nome não verificado)` })).toBeVisible();
  await expect(bob.getByLabel("Escreva uma mensagem")).toBeDisabled();

  // ATAQUE: membro novo (não verificado) não recebe a chave sozinho; a Alice decide.
  await alice.getByRole("button", { name: "Membros e ajustes" }).click();
  await expect(alice.getByText("Aguardando a chave", { exact: true })).toBeVisible({ timeout: 15000 });
  await alice.getByRole("button", { name: "Entregar a chave" }).click();
  await expect(bob.getByRole("heading", { name: ROOM })).toBeVisible({ timeout: 15000 }); // nome assinado pela dona, conferido
  await expect(bob.getByLabel("Escreva uma mensagem")).toBeEnabled();

  // Mensagens; ATAQUE: XSS no texto aparece como TEXTO.
  await bob.getByLabel("Escreva uma mensagem").fill("olá da Bob");
  await bob.getByRole("button", { name: "Enviar" }).click();
  await expect(alice.getByText("olá da Bob")).toBeVisible({ timeout: 15000 });
  await bob.getByLabel("Escreva uma mensagem").fill(XSS);
  await bob.getByRole("button", { name: "Enviar" }).click();
  await expect(alice.locator(".bubble .text", { hasText: XSS })).toBeVisible({ timeout: 15000 });
  expect(await alice.locator(".messages img").count()).toBe(0);
  expect(await alice.title()).not.toBe("XSS");
  await expect(alice.locator(".bubble", { hasText: "olá da Bob" }).getByText("não verificado")).toBeVisible();

  // Número de segurança: o mesmo dos dois lados; a Alice confirma.
  await alice.getByRole("button", { name: "Número de segurança" }).click();
  const aliceDigits = await alice.locator(".digits").innerText();
  await bob.getByRole("button", { name: "Membros e ajustes" }).click();
  await bob.getByRole("button", { name: "Número de segurança" }).click();
  const bobDigits = await bob.locator(".digits").innerText();
  expect(aliceDigits).toMatch(/^(\d{5} ){11}\d{5}$/);
  expect(bobDigits).toBe(aliceDigits);
  await alice.getByRole("button", { name: "Marcar como verificado" }).click();
  await expect(alice.locator(".panel .chip.ok", { hasText: "verificado" })).toBeVisible();
  await bob.getByRole("button", { name: "Fechar painel" }).first().click();

  // Efêmera (C2): 1 minuto, com contagem regressiva no Bob.
  await alice.getByLabel("Expiração").selectOption("1min");
  await alice.getByLabel("Escreva uma mensagem").fill("some em breve");
  await alice.getByRole("button", { name: "Enviar" }).click();
  await expect(bob.locator(".bubble", { hasText: "some em breve" }).getByText(/some em \d+ min \d{2} s/)).toBeVisible({ timeout: 15000 });
  await bob.clock.fastForward("03:00");
  await expect(bob.getByText("some em breve")).toHaveCount(0, { timeout: 10000 });
  await expect(bob.getByText("olá da Bob")).toBeVisible(); // a não efêmera continua

  // Recarregar: sessão retomada pelo /me, cofre desbloqueado, histórico
  // decifrado no navegador; e o botão Bloquear tira as chaves da memória.
  await alice.reload();
  await expect(alice.getByRole("heading", { name: "Desbloquear o cofre" })).toBeVisible({ timeout: 15000 });
  await alice.getByLabel("Senha de cifragem", { exact: true }).fill(PASS);
  await alice.getByRole("button", { name: "Desbloquear" }).click();
  await expect(alice.getByRole("heading", { name: ROOM })).toBeVisible({ timeout: 20000 });
  await expect(alice.getByText("olá da Bob")).toBeVisible({ timeout: 15000 }); // veio do histórico
  await alice.getByRole("button", { name: "Bloquear" }).click();
  await expect(alice.getByRole("heading", { name: "Desbloquear o cofre" })).toBeVisible();
  await expect(alice.getByText("olá da Bob")).toHaveCount(0);
  await alice.getByLabel("Senha de cifragem", { exact: true }).fill("senha-errada-de-cifragem");
  await alice.getByRole("button", { name: "Desbloquear" }).click();
  await expect(alice.getByText(/Senha de cifragem errada/)).toBeVisible({ timeout: 15000 });
  await alice.getByLabel("Senha de cifragem", { exact: true }).fill(PASS);
  await alice.getByRole("button", { name: "Desbloquear" }).click();
  await expect(alice.getByRole("heading", { name: ROOM })).toBeVisible({ timeout: 20000 });
  await alice.getByRole("button", { name: "Membros e ajustes" }).click();

  // Nada em localStorage/sessionStorage; o IndexedDB não tem texto claro.
  for (const page of [alice, bob]) {
    expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
    const dump = await page.evaluate(
      () =>
        new Promise((resolve, reject) => {
          const req = indexedDB.open("secure-chat");
          req.onerror = () => reject(req.error);
          req.onsuccess = () => {
            const all = req.result.transaction("vault").objectStore("vault").getAll();
            all.onsuccess = () => resolve(JSON.stringify(all.result));
          };
        })
    );
    expect(dump).toContain("secure-chat-keystore");
    for (const secret of ["olá da Bob", "some em breve", ROOM, "ecdhPriv"]) expect(dump).not.toContain(secret);
  }

  // A Alice remove o Bob: ele é avisado; a chave é trocada (v2).
  await alice.getByRole("button", { name: "Remover" }).click();
  await expect(alice.getByText(/Membro removido\. Convite novo \(mostrado só agora\): [0-9a-f]{32}/)).toBeVisible({ timeout: 15000 });
  await expect(bob.getByText("Você não é mais membro desta sala.")).toBeVisible({ timeout: 15000 });
  await expect(alice.getByText(/Chave da sala trocada \(v2\)/)).toBeVisible({ timeout: 15000 });

  // Celular (C3, 390 px): a lateral vira gaveta; Esc fecha.
  await alice.setViewportSize({ width: 390, height: 844 });
  await alice.getByRole("button", { name: "Fechar painel" }).first().click();
  await expect(alice.locator("#rooms-drawer")).toBeHidden();
  await alice.getByRole("button", { name: "Salas", exact: true }).click();
  await expect(alice.locator("#rooms-drawer")).toBeVisible();
  await alice.keyboard.press("Escape");
  await expect(alice.locator("#rooms-drawer")).toBeHidden();

  // Nenhuma violação de CSP nem erro de JavaScript em nenhuma das páginas.
  for (const [who, bag] of Object.entries(logs)) {
    expect({ who, problems: bag.filter((l) => /Content Security Policy|pageerror|Refused to/.test(l)) }).toEqual({ who, problems: [] });
  }
  await aliceCtx.close();
  await bobCtx.close();
});
