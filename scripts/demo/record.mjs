/**
 * Records a short walkthrough of the API in Swagger UI.
 *
 * Usage (with the API running on API_URL and JUDGE_INVITE_CODE set to the same value):
 *   npm i --no-save playwright && npx playwright install chromium
 *   node scripts/demo/record.mjs
 *
 * Writes a .webm video to scripts/demo/out/. Convert it with ffmpeg (see demo workflow).
 */
import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright";

const API = process.env.API_URL || "http://localhost:4000";
const INVITE = process.env.JUDGE_INVITE_CODE || "demo-judge";
const OUT_DIR = path.resolve("scripts/demo/out");

async function call(method, url, { token, body } = {}) {
  const res = await fetch(`${API}${url}`, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`${method} ${url} -> ${res.status} ${JSON.stringify(data)}`);
  return data;
}

const signup = (name, email, role, extra = {}) =>
  call("POST", "/auth/signup", {
    body: { name, email, password: "Passw0rd!", role, ...extra },
  }).then((r) => r.token);

/** Seeds a realistic scene: a few cases, one approved with jury votes already cast. */
async function seed() {
  const luigi = await signup("Chef Luigi", "luigi@example.com", "DEFENDANT");
  const remy = await signup("Remy", "remy@example.com", "PLAINTIFF");
  const judge = await signup("Judge Julia", "julia@example.com", "JUDGE", { inviteCode: INVITE });
  const jurors = await Promise.all(
    ["Jane", "Ravi", "Mei"].map((n) => signup(n, `${n.toLowerCase()}@example.com`, "JUROR")),
  );

  const fileCase = async (token, title, partyName, argumentText) => {
    const form = new FormData();
    form.set("title", title);
    form.set("partyName", partyName);
    form.set("argumentText", argumentText);
    const res = await fetch(`${API}/case/submit`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: form,
    });
    return res.json();
  };

  const pie = await fileCase(
    luigi,
    "The Case of the Stolen Pie",
    "Chef Luigi",
    "I did not steal the pie. I was proofing dough all night.",
  );
  await fileCase(
    remy,
    "Too Much Salt in the Ratatouille",
    "Remy",
    "The sous-chef sabotaged my signature dish.",
  );
  await fileCase(
    remy,
    "Who Left the Oven On?",
    "Remy",
    "The night shift left the oven on for 9 hours.",
  );

  await call("PATCH", `/case/approve/${pie._id}`, { token: judge });
  await call("POST", `/jury/vote/${pie._id}`, { token: jurors[0], body: { choice: "not_guilty" } });
  await call("POST", `/jury/vote/${pie._id}`, { token: jurors[1], body: { choice: "not_guilty" } });
  await call("POST", `/jury/vote/${pie._id}`, { token: jurors[2], body: { choice: "guilty" } });

  return { judge, caseId: pie._id };
}

async function caption(page, text) {
  await page.evaluate((t) => {
    let el = document.getElementById("demo-caption");
    if (!el) {
      el = document.createElement("div");
      el.id = "demo-caption";
      Object.assign(el.style, {
        position: "fixed",
        left: "50%",
        bottom: "28px",
        transform: "translateX(-50%)",
        background: "rgba(17, 24, 39, 0.92)",
        color: "#fff",
        font: "600 20px/1.4 system-ui, sans-serif",
        padding: "12px 22px",
        borderRadius: "10px",
        zIndex: 99999,
        boxShadow: "0 8px 24px rgba(0,0,0,.25)",
        maxWidth: "80%",
        textAlign: "center",
      });
      document.body.appendChild(el);
    }
    el.textContent = t;
  }, text);
}

async function slowType(locator, text) {
  await locator.click();
  await locator.fill("");
  await locator.pressSequentially(text, { delay: 25 });
}

async function main() {
  const { judge, caseId } = await seed();
  fs.mkdirSync(OUT_DIR, { recursive: true });

  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    recordVideo: { dir: OUT_DIR, size: { width: 1280, height: 800 } },
  });
  const page = await context.newPage();
  const pause = (ms) => page.waitForTimeout(ms);

  try {
    await page.goto(`${API}/docs`);
    await page.locator(".opblock").first().waitFor();
    await caption(page, "Chef's Court API: interactive docs at /docs");
    await pause(2500);
    await page.mouse.wheel(0, 500);
    await pause(1500);
    await page.mouse.wheel(0, -500);
    await pause(800);

    // Authorize as the judge
    await caption(page, "Sign in as the judge (JWT bearer token)");
    await page.locator(".auth-wrapper button.authorize").click();
    await slowType(page.locator(".modal-ux input").first(), judge.slice(0, 60));
    await page.locator(".modal-ux input").first().fill(judge);
    await pause(400);
    await page.locator(".modal-ux button.authorize").click();
    await pause(900);
    await page.locator(".modal-ux button.btn-done").click();
    await pause(800);

    // List cases
    const list = page.locator("#operations-Cases-listCases");
    await caption(page, "List cases with pagination, status filter and search");
    await list.scrollIntoViewIfNeeded();
    await list.locator(".opblock-summary").first().click();
    await pause(1000);
    await list.locator("button.try-out__btn").click();
    await pause(500);
    await slowType(list.locator('input[placeholder="q"]'), "pie");
    await pause(400);
    await list.locator("button.execute").click();
    await list.locator(".live-responses-table").waitFor();
    await pause(600);
    await list.locator(".live-responses-table").scrollIntoViewIfNeeded();
    await pause(3000);
    await list.locator(".opblock-summary").first().click();
    await pause(600);

    // Jury tally
    const results = page.locator("#operations-Jury-getResults");
    await caption(page, "The jury has voted: check the tally");
    await results.scrollIntoViewIfNeeded();
    await results.locator(".opblock-summary").first().click();
    await pause(800);
    await results.locator("button.try-out__btn").click();
    await slowType(results.locator('input[placeholder="caseId"]'), caseId);
    await results.locator("button.execute").click();
    await results.locator(".live-responses-table").waitFor();
    await results.locator(".live-responses-table").scrollIntoViewIfNeeded();
    await pause(3000);
    await results.locator(".opblock-summary").first().click();
    await pause(600);

    // Close the case with a verdict
    const close = page.locator("#operations-Cases-closeCase");
    await caption(page, "The judge closes the case, and the verdict follows the jury majority");
    await close.scrollIntoViewIfNeeded();
    await close.locator(".opblock-summary").first().click();
    await pause(800);
    await close.locator("button.try-out__btn").click();
    await slowType(close.locator('input[placeholder="id"]'), caseId);
    const body = close.locator("textarea.body-param__text");
    if (await body.count()) await body.fill("{}");
    await pause(400);
    await close.locator("button.execute").click();
    await close.locator(".live-responses-table").waitFor();
    await close.locator(".live-responses-table").scrollIntoViewIfNeeded();
    await pause(1200);
    await caption(page, "Verdict: not guilty (2–1). The case is now CLOSED and locked.");
    await pause(4000);
  } catch (err) {
    await page.screenshot({ path: path.join(OUT_DIR, "failure.png") });
    throw err;
  } finally {
    await context.close();
    await browser.close();
  }

  const video = fs.readdirSync(OUT_DIR).find((f) => f.endsWith(".webm"));
  fs.renameSync(path.join(OUT_DIR, video), path.join(OUT_DIR, "demo.webm"));
  console.log("Saved", path.join(OUT_DIR, "demo.webm"));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
