// Real Chromium test driven by verify.py. Prints one JSON document to stdout.
// usage: node browser_test.cjs <mode> <targetPort> <attackerPort> [waitSeconds]
// The target is http://127.0.0.1:<targetPort>. The attacker page is served from
// http://localhost:<attackerPort>. 127.0.0.1 and localhost are different sites.
const { chromium } = require('playwright');

async function main() {
  const [mode, tPort, aPort, waitArg] = process.argv.slice(2);
  const waitSeconds = Number(waitArg || 0);
  const target = `http://127.0.0.1:${tPort}`;
  const attacker = `http://localhost:${aPort}`;
  const state = async () => (await fetch(`${target}/_state`)).json();
  const reset = async () => fetch(`${target}/_reset`);
  const browser = await chromium.launch();
  const out = { browser: 'chromium ' + browser.version(), mode, cases: [] };
  const samesites = mode === 'vulnerable' ? ['none', 'lax', 'strict', 'unset'] : ['unset'];
  for (const ss of samesites) {
    for (const attack of ['post', 'get']) {
      await reset();
      const ctx = await browser.newContext();
      const page = await ctx.newPage();
      await page.goto(`${target}/login?user=alice&samesite=${ss}`);
      const cookies = await ctx.cookies(target);
      const cookie = cookies.map(c => ({ name: c.name, sameSite: c.sameSite, secure: c.secure, httpOnly: c.httpOnly }));
      const before = (await state()).log.length;
      const nav = page.waitForURL(u => u.href.startsWith(target + '/account'), { timeout: 5000 }).catch(() => null);
      await page.goto(`${attacker}/attack-${attack}.html`);
      await nav;
      await page.waitForLoadState('load');
      const s = await state();
      const req = s.log.slice(before).filter(r => r.path.startsWith('/account'))[0] || null;
      out.cases.push({ attack, requested_samesite: ss, stored_cookie: cookie, request_seen: req, email_after: s.email });
      await ctx.close();
    }
  }
  if (mode === 'vulnerable' && waitSeconds > 0) { // Lax-by-default POST window: cookie older than two minutes
    await reset();
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(`${target}/login?user=alice&samesite=unset`);
    await new Promise(r => setTimeout(r, waitSeconds * 1000));
    const before = (await state()).log.length;
    const nav = page.waitForURL(u => u.href.startsWith(target + '/account'), { timeout: 5000 }).catch(() => null);
    await page.goto(`${attacker}/attack-post.html`);
    await nav;
    await page.waitForLoadState('load');
    const s = await state();
    const req = s.log.slice(before).filter(r => r.path.startsWith('/account'))[0] || null;
    out.cases.push({ attack: 'post', requested_samesite: 'unset', cookie_age_seconds: waitSeconds,
      request_seen: req, email_after: s.email });
    await ctx.close();
  }
  if (mode === 'fixed') { // positive control: the real form, same origin, token included
    await reset();
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(`${target}/login?user=alice`);
    await page.goto(`${target}/account`);
    await page.fill('input[name=email]', 'alice-new@example.test');
    await Promise.all([page.waitForLoadState('load'), page.click('button')]);
    const s = await state();
    out.cases.push({ attack: 'legitimate-form', requested_samesite: 'lax',
      request_seen: s.log.filter(r => r.method === 'POST')[0] || null, email_after: s.email });
    await ctx.close();
  }
  await browser.close();
  console.log(JSON.stringify(out));
}
main().catch(e => { console.error(String(e)); process.exit(1); });
