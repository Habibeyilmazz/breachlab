// Records the README demo: break the invoice search with SQL injection in a real browser.
//   python -m breachlab --port 4162 --no-reload &   then   node e2e/demo.cjs   (writes e2e/out/demo.webm)
// docs/demo.gif is made from it with ffmpeg (see CONTRIBUTING.md).
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");

const BASE = (process.env.BREACHLAB_URL || "http://127.0.0.1:4160").replace(/\/$/, "");
const OUT = path.join(__dirname, "out");

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch();
  // Reset first, without recording.
  const setup = await browser.newPage();
  setup.on("dialog", (d) => d.accept());
  await setup.goto(`${BASE}/lab`);
  await setup.getByRole("button", { name: "Reset data and progress" }).click();
  await setup.waitForURL(/reset=1/);
  await setup.close();

  const context = await browser.newContext({
    viewport: { width: 960, height: 600 },
    recordVideo: { dir: OUT, size: { width: 960, height: 600 } },
  });
  const page = await context.newPage();
  const pause = (ms) => page.waitForTimeout(ms);
  await page.goto(`${BASE}/lab/c/sqli`);
  await pause(2500);
  await page.goto(`${BASE}/login`);
  await page.getByLabel("Username").fill("alice");
  await page.getByLabel("Password").fill("alice-demo");
  await pause(500);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL(`${BASE}/invoices`);
  await pause(1500);
  await page.getByLabel("Search your invoices by customer").pressSequentially("' OR 1=1--", { delay: 140 });
  await pause(700);
  await page.getByRole("button", { name: "Search" }).click();
  await page.locator(".flagbanner").waitFor();
  await pause(3500);
  const video = page.video();
  await context.close();
  await video.saveAs(path.join(OUT, "demo.webm"));
  await browser.close();
})();
