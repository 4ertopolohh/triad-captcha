import { expect, test, type APIRequestContext } from '@playwright/test';

const API_ORIGIN = 'https://api.triad.test:9443';
const APP_ORIGIN = 'https://app.triad.test:9443';
const CROSS_SITE_ORIGIN = 'https://trusted.other.test:9443';
const CONTROL_ORIGIN = 'https://127.0.0.1:9443';
const DEMO_ORIGIN = process.env.TRIADCAPTCHA_BROWSER_DEMO_URL ?? 'http://localhost:8080';

async function resetCounters(request: APIRequestContext) {
  await request.get(`${CONTROL_ORIGIN}/reset`, { ignoreHTTPSErrors: true });
}

test('demo SPA, static assets, API, and proof worker satisfy the enforced CSP', async ({
  page,
  request,
}) => {
  const violations: string[] = [];
  const failedResources: string[] = [];
  const protectedStatuses: number[] = [];
  let workerCount = 0;

  await page.addInitScript(() => {
    globalThis.addEventListener('securitypolicyviolation', (event) => {
      const target = globalThis as typeof globalThis & { __cspViolations?: string[] };
      target.__cspViolations ??= [];
      target.__cspViolations.push(`${event.violatedDirective}:${event.blockedURI}`);
    });
  });
  page.on('requestfailed', (request) => failedResources.push(request.url()));
  page.on('worker', () => { workerCount += 1; });
  page.on('response', (response) => {
    if (new URL(response.url()).pathname === '/api/register/') {
      protectedStatuses.push(response.status());
    }
  });

  await page.goto('/');
  await expect.poll(async () => (
    await page.context().cookies()
  ).some((cookie) => cookie.name === 'csrftoken')).toBe(true);
  const form = page.locator('form').first();
  await form.locator('input[name="email"]').fill('browser@example.test');
  await form.locator('input[name="password"]').fill('demo-password');
  await form.locator('button[type="submit"]').click();
  await expect.poll(() => protectedStatuses).toEqual([428, 200]);

  const cspViolations = await page.evaluate(() => (
    (globalThis as typeof globalThis & { __cspViolations?: string[] }).__cspViolations ?? []
  ));
  expect(workerCount).toBeGreaterThan(0);
  expect(cspViolations).toEqual([]);
  expect(failedResources).toEqual([]);

  await resetCounters(request);
  const undeclaredConnectionRejected = await page.evaluate(async (target) => {
    try {
      await fetch(target);
      return false;
    } catch {
      return true;
    }
  }, 'https://untrusted.other.test:9443/sink');
  expect(undeclaredConnectionRejected).toBe(true);
  expect((await (await request.get(`${CONTROL_ORIGIN}/stats`, {
    ignoreHTTPSErrors: true,
  })).json()).sink).toBe(0);
  const negativeViolations = await page.evaluate(() => (
    (globalThis as typeof globalThis & { __cspViolations?: string[] }).__cspViolations ?? []
  ));
  expect(negativeViolations.some((item) => item.startsWith('connect-src'))).toBe(true);
});

test('demo frame-ancestors policy blocks embedding even from a blank parent', async ({ page }) => {
  const refused = page.waitForEvent('console', {
    predicate: (message) => message.text().includes('frame-ancestors'),
    timeout: 10_000,
  });
  await page.setContent(`<iframe title="blocked demo" src="${DEMO_ORIGIN}/"></iframe>`);
  await refused;

  expect(page.frames().some((frame) => frame.url().startsWith(DEMO_ORIGIN))).toBe(false);
});

test('same-site HTTPS subdomain sends the default Lax context cookie', async ({ page, request }) => {
  await resetCounters(request);
  await page.goto(`${API_ORIGIN}/set-cookie?mode=lax`);
  await page.goto(`${APP_ORIGIN}/app`);

  const status = await page.evaluate(async (apiOrigin) => {
    const response = await fetch(`${apiOrigin}/business`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    return response.status;
  }, API_ORIGIN);

  expect(status).toBe(200);
  await expect.poll(async () => (await request.get(`${CONTROL_ORIGIN}/stats`, {
    ignoreHTTPSErrors: true,
  })).json()).toMatchObject({ business: 1 });
});

test('cross-site Lax is gated, while explicit None Secure with narrow CORS succeeds', async ({
  page,
  request,
}) => {
  await resetCounters(request);
  await page.goto(`${API_ORIGIN}/set-cookie?mode=lax`);
  await page.goto(`${CROSS_SITE_ORIGIN}/app`);

  const laxStatus = await page.evaluate(async (apiOrigin) => (
    await fetch(`${apiOrigin}/business`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })
  ).status, API_ORIGIN);
  expect(laxStatus).toBe(403);
  expect((await (await request.get(`${CONTROL_ORIGIN}/stats`, {
    ignoreHTTPSErrors: true,
  })).json()).business).toBe(0);

  await page.goto(`${API_ORIGIN}/set-cookie?mode=none`);
  await page.goto(`${CROSS_SITE_ORIGIN}/app`);
  const noneStatus = await page.evaluate(async (apiOrigin) => (
    await fetch(`${apiOrigin}/business`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })
  ).status, API_ORIGIN);
  expect(noneStatus).toBe(200);
  expect((await (await request.get(`${CONTROL_ORIGIN}/stats`, {
    ignoreHTTPSErrors: true,
  })).json()).business).toBe(1);
});

test('redirect mode prevents protected headers reaching an untrusted origin', async ({
  page,
  request,
}) => {
  await resetCounters(request);
  await page.goto(`${APP_ORIGIN}/app`);

  const rejected = await page.evaluate(async (apiOrigin) => {
    try {
      await fetch(`${apiOrigin}/redirect`, {
        credentials: 'include',
        headers: { 'X-TriadCAPTCHA-Site-Key': 'tc_site_browser_test' },
        redirect: 'error',
      });
      return false;
    } catch {
      return true;
    }
  }, API_ORIGIN);

  expect(rejected).toBe(true);
  expect((await (await request.get(`${CONTROL_ORIGIN}/stats`, {
    ignoreHTTPSErrors: true,
  })).json()).sink).toBe(0);
});
