import type { Challenge } from 'altcha-lib';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import {
  createProtectedFetch,
  createTriadCaptchaClient,
  TRIADCAPTCHA_HEADERS,
  TriadCaptchaError,
} from '../src';

const challenge: Challenge = {
  parameters: {
    algorithm: 'PBKDF2/SHA-256',
    cost: 5_000,
    expiresAt: Math.floor(Date.now() / 1_000) + 60,
    keyLength: 32,
    keyPrefix: '0011',
    nonce: '00112233445566778899aabbccddeeff',
    salt: 'ffeeddccbbaa99887766554433221100',
  },
  signature: 'server-signature',
};

beforeAll(() => vi.stubGlobal('location', new URL('http://localhost/')));
afterAll(() => vi.unstubAllGlobals());

function jsonResponse(body: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function decodeBase64UrlJson(value: string): unknown {
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') +
    '='.repeat((4 - (value.length % 4)) % 4);
  return JSON.parse(atob(padded)) as unknown;
}

describe('protected fetch', () => {
  it('binds the default browser fetch to globalThis', async () => {
    const originalFetch = globalThis.fetch;
    const receiverAwareFetch = vi.fn(function (this: unknown) {
      if (this !== globalThis) throw new TypeError('Illegal invocation');
      return Promise.resolve(jsonResponse({ ok: true }));
    }) as unknown as typeof fetch;
    vi.stubGlobal('fetch', receiverAwareFetch);
    try {
      const protectedFetch = createProtectedFetch({ siteKey: 'site_public' });
      await expect(protectedFetch('/api/contact/', { method: 'POST' }, {
        action: 'contact',
      })).resolves.toBeInstanceOf(Response);
    } finally {
      vi.stubGlobal('fetch', originalFetch);
    }
  });

  it('returns a low-risk response without requesting a challenge', async () => {
    const requests: Request[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      requests.push(input as Request);
      return jsonResponse({ ok: true });
    }) as typeof fetch;
    const protectedFetch = createProtectedFetch({
      fetch: fetchMock,
      siteKey: 'site_public',
    });

    const response = await protectedFetch('/api/contact/', { method: 'POST' }, {
      action: 'contact',
      metadata: { focus_count: 2 },
    });

    expect(response.status).toBe(200);
    expect(requests).toHaveLength(1);
    const request = requests[0]!;
    expect(request.headers.get(TRIADCAPTCHA_HEADERS.siteKey)).toBe('site_public');
    expect(request.headers.get(TRIADCAPTCHA_HEADERS.action)).toBe('contact');
    expect(request.headers.has(TRIADCAPTCHA_HEADERS.proof)).toBe(false);
    expect(
      decodeBase64UrlJson(request.headers.get(TRIADCAPTCHA_HEADERS.metadata)!),
    ).toEqual({ focus_count: 2 });
  });

  it('fetches, solves, and retries once while preserving the request body', async () => {
    const requests: Request[] = [];
    let protectedCalls = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const request = input as Request;
      requests.push(request);
      const url = new URL(request.url);
      if (url.pathname === '/api/triadcaptcha/challenge/') {
        return jsonResponse({ challenge });
      }
      protectedCalls += 1;
      return protectedCalls === 1
        ? jsonResponse({ error: { code: 'ANTIBOT_CHALLENGE_REQUIRED' } }, 428)
        : jsonResponse({ created: true }, 201);
    }) as typeof fetch;
    const solver = vi.fn(async () => 'cHJvb2Y=');
    const protectedFetch = createProtectedFetch({
      fetch: fetchMock,
      siteKey: 'site_public',
      solver,
    });

    const response = await protectedFetch(
      '/api/register/',
      {
        body: JSON.stringify({ email: 'person@example.test' }),
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': 'csrf-token',
          [TRIADCAPTCHA_HEADERS.proof]: 'stale-proof',
        },
        method: 'POST',
      },
      { action: 'register', metadata: { input_count: 4 } },
    );

    expect(response.status).toBe(201);
    expect(solver).toHaveBeenCalledOnce();
    expect(requests).toHaveLength(3);
    const [initial, challengeRequest, retry] = requests;
    expect(new URL(challengeRequest!.url).searchParams.get('action')).toBe('register');
    expect(challengeRequest!.credentials).toBe('include');
    expect(initial!.redirect).toBe('error');
    expect(challengeRequest!.redirect).toBe('error');
    expect(retry!.redirect).toBe('error');
    expect(initial!.headers.has(TRIADCAPTCHA_HEADERS.proof)).toBe(false);
    expect(retry!.headers.get(TRIADCAPTCHA_HEADERS.proof)).toBe('cHJvb2Y=');
    expect(retry!.headers.get('X-CSRFToken')).toBe('csrf-token');
    await expect(initial!.clone().text()).resolves.toBe(
      JSON.stringify({ email: 'person@example.test' }),
    );
    await expect(retry!.clone().text()).resolves.toBe(
      JSON.stringify({ email: 'person@example.test' }),
    );
  });

  it('does not recurse when the protected retry asks for another challenge', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const request = input as Request;
      return new URL(request.url).pathname === '/api/triadcaptcha/challenge/'
        ? jsonResponse(challenge)
        : jsonResponse({ code: 'ANTIBOT_CHALLENGE_REQUIRED' }, 428);
    }) as typeof fetch;
    const client = createTriadCaptchaClient({
      fetch: fetchMock,
      siteKey: 'site_public',
      solver: async () => 'cHJvb2Y=',
    });

    await expect(
      client.protectedFetch('/api/login/', { method: 'POST' }, { action: 'login' }),
    ).rejects.toMatchObject({
      code: 'ANTIBOT_CHALLENGE_REQUIRED',
      status: 428,
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('surfaces a stable block code and retry_after without server reasons', async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(
        { error: { code: 'ANTIBOT_BLOCKED', reason: 'private-rule', retry_after: 12.2 } },
        403,
      ),
    ) as typeof fetch;
    const protectedFetch = createProtectedFetch({ fetch: fetchMock, siteKey: 'site_public' });

    const error = await protectedFetch(
      '/api/password-reset/',
      { method: 'POST' },
      { action: 'password_reset' },
    ).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(TriadCaptchaError);
    expect(error).toMatchObject({ code: 'ANTIBOT_BLOCKED', retryAfter: 13, status: 403 });
    expect((error as Error).message).toBe('ANTIBOT_BLOCKED');
  });

  it('returns non-antibot business errors unchanged', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ code: 'INVALID_LOGIN' }, 400)) as typeof fetch;
    const protectedFetch = createProtectedFetch({ fetch: fetchMock, siteKey: 'site_public' });

    const response = await protectedFetch(
      '/api/login/',
      { method: 'POST' },
      { action: 'login' },
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ code: 'INVALID_LOGIN' });
  });

  it('does not treat an arbitrary 428 response as an antibot challenge', async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ code: 'PRECONDITION_REQUIRED' }, 428),
    ) as typeof fetch;
    const protectedFetch = createProtectedFetch({ fetch: fetchMock, siteKey: 'site_public' });

    const response = await protectedFetch(
      '/api/profile/',
      { method: 'POST' },
      { action: 'profile_update' },
    );

    expect(response.status).toBe(428);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('returns status-only business rate/outage responses unchanged', async () => {
    for (const status of [429, 503]) {
      const fetchMock = vi.fn(async () => new Response('', { status })) as typeof fetch;
      const protectedFetch = createProtectedFetch({ fetch: fetchMock, siteKey: 'site_public' });

      const response = await protectedFetch(
        '/api/business-operation/',
        { method: 'POST' },
        { action: 'business_operation' },
      );

      expect(response.status).toBe(status);
      expect(fetchMock).toHaveBeenCalledOnce();
    }
  });

  it('rejects cross-origin endpoints before sending site key or metadata', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ ok: true })) as typeof fetch;
    const protectedFetch = createProtectedFetch({ fetch: fetchMock, siteKey: 'site_public' });

    await expect(
      protectedFetch(
        'https://third-party.invalid/collect',
        { method: 'POST' },
        { action: 'contact' },
      ),
    ).rejects.toMatchObject({ code: 'ANTIBOT_CONFIGURATION_ERROR' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('allows an explicitly trusted exact origin for protected and challenge requests', async () => {
    const requests: Request[] = [];
    let protectedCalls = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const request = input as Request;
      requests.push(request);
      if (new URL(request.url).pathname === '/api/triadcaptcha/challenge/') {
        return jsonResponse({ challenge });
      }
      protectedCalls += 1;
      return protectedCalls === 1
        ? jsonResponse({ error: { code: 'ANTIBOT_CHALLENGE_REQUIRED' } }, 428)
        : jsonResponse({ ok: true });
    }) as typeof fetch;
    const protectedFetch = createProtectedFetch({
      challengeUrl: 'https://api.example.test/api/triadcaptcha/challenge/',
      fetch: fetchMock,
      siteKey: 'site_public',
      solver: async () => 'cHJvb2Y=',
      trustedOrigins: ['https://api.example.test'],
    });

    await expect(protectedFetch(
      'https://api.example.test/api/login/',
      { credentials: 'include', method: 'POST' },
      { action: 'login' },
    )).resolves.toMatchObject({ status: 200 });
    expect(requests).toHaveLength(3);
    expect(requests[1]!.credentials).toBe('include');
    expect(requests.every((request) => request.redirect === 'error')).toBe(true);
  });

  it.each([
    ['https://*.example.test'],
    ['https://api.example.test/path'],
    ['https://user:pass@api.example.test'],
    ['ftp://api.example.test'],
  ])('rejects an invalid trusted origin: %s', (trustedOrigin) => {
    expect(() => createProtectedFetch({
      siteKey: 'site_public',
      trustedOrigins: [trustedOrigin],
    })).toThrowError(TriadCaptchaError);
  });

  it('maps an unavailable challenge endpoint to the public service code', async () => {
    let call = 0;
    const fetchMock = vi.fn(async () => {
      call += 1;
      return call === 1
        ? jsonResponse({ code: 'ANTIBOT_CHALLENGE_REQUIRED' }, 428)
        : new Response('', { status: 503 });
    }) as typeof fetch;
    const protectedFetch = createProtectedFetch({ fetch: fetchMock, siteKey: 'site_public' });

    await expect(
      protectedFetch('/api/code/', { method: 'POST' }, { action: 'send_code' }),
    ).rejects.toMatchObject({ code: 'ANTIBOT_SERVICE_UNAVAILABLE', status: 503 });
  });
});
