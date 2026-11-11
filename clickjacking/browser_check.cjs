// Usage: node browser_check.cjs framed|direct <attacker_url> <target_url>
// Needs the playwright package on NODE_PATH. Prints one JSON object.
const { chromium } = require("playwright");
(async () => {
  const [scenario, attackerUrl, targetUrl] = process.argv.slice(2);
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 500, height: 400 } });
  const messages = [];
  page.on("console", (m) => messages.push(m.text()));
  const out = { scenario, browser: "chromium " + browser.version() };
  if (scenario === "framed") {
    await page.goto(attackerUrl + "/attack");
    await page.waitForTimeout(1000);
    const child = page.frames().find((f) => f !== page.mainFrame());
    out.frame_url = child ? child.url() : null;
    out.frame_has_delete_button = child ? (await child.locator("#delete").count()) === 1 : false;
    out.click_point = [200, 125];
    await page.mouse.click(200, 125);
  } else {
    await page.goto(targetUrl + "/account");
    out.top_level_has_delete_button = (await page.locator("#delete").count()) === 1;
    await page.locator("#delete").click();
  }
  await page.waitForTimeout(500);
  out.console = messages;
  await browser.close();
  console.log(JSON.stringify(out));
})().catch((e) => { console.log(JSON.stringify({ error: String(e) })); process.exit(1); });
