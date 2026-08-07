// @vitest-environment jsdom

import { act, renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { TRIADCAPTCHA_HEADERS, TriadCaptchaError, useTriadCaptcha } from '../src';

function decodeBase64Url(value: string): Record<string, unknown> {
  const standard = value.replaceAll('-', '+').replaceAll('_', '/') +
    '='.repeat((4 - (value.length % 4)) % 4);
  return JSON.parse(atob(standard)) as Record<string, unknown>;
}

describe('useTriadCaptcha', () => {
  it('adds locally collected interaction counts', async () => {
    const requests: Request[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      requests.push(input as Request);
      return new Response('{}', {
        headers: { 'Content-Type': 'application/json' },
        status: 200,
      });
    }) as typeof fetch;
    const { result } = renderHook(() =>
      useTriadCaptcha({ fetch: fetchMock, siteKey: 'site_public' }),
    );

    act(() => {
      result.current.interactionProps.onFocusCapture();
      result.current.interactionProps.onInputCapture();
      result.current.interactionProps.onKeyDownCapture();
    });
    await act(async () => {
      await result.current.protectedFetch(
        '/api/login/',
        { method: 'POST' },
        { action: 'login', metadata: { was_autofilled: true } },
      );
    });

    const metadata = decodeBase64Url(
      requests[0]!.headers.get(TRIADCAPTCHA_HEADERS.metadata)!,
    );
    expect(metadata).toMatchObject({
      focus_count: 1,
      input_count: 1,
      keyboard_count: 1,
      was_autofilled: true,
    });
    expect(result.current.isVerifying).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it('retains a stable antibot error for localized UI', async () => {
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ code: 'ANTIBOT_RATE_LIMITED', retry_after: 5 }), {
        headers: { 'Content-Type': 'application/json' },
        status: 429,
      }),
    ) as typeof fetch;
    const { result } = renderHook(() =>
      useTriadCaptcha({ fetch: fetchMock, siteKey: 'site_public' }),
    );

    await act(async () => {
      await expect(
        result.current.protectedFetch(
          '/api/send-code/',
          { method: 'POST' },
          { action: 'send_code' },
        ),
      ).rejects.toBeInstanceOf(TriadCaptchaError);
    });
    expect(result.current.error).toMatchObject({
      code: 'ANTIBOT_RATE_LIMITED',
      retryAfter: 5,
    });

    act(() => result.current.resetError());
    expect(result.current.error).toBeNull();
  });
});
