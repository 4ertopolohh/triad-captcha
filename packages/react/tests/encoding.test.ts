import { describe, expect, it } from 'vitest';

import { encodeAltchaPayload, encodeMetadata, sanitizeMetadata } from '../src/encoding';
import type { AltchaPayload, WeakMetadata } from '../src/types';

function decodeBase64(value: string): unknown {
  return JSON.parse(new TextDecoder().decode(
    Uint8Array.from(atob(value), (character) => character.charCodeAt(0)),
  )) as unknown;
}

function decodeBase64Url(value: string): unknown {
  const standard = value.replaceAll('-', '+').replaceAll('_', '/') +
    '='.repeat((4 - (value.length % 4)) % 4);
  return decodeBase64(standard);
}

describe('wire encoding', () => {
  it('encodes the ALTCHA v2 payload as Python-compatible standard Base64', () => {
    const payload: AltchaPayload = {
      challenge: {
        parameters: {
          algorithm: 'PBKDF2/SHA-256',
          cost: 1,
          keyLength: 32,
          keyPrefix: '00',
          nonce: '00',
          salt: '11',
        },
        signature: 'signed',
      },
      solution: { counter: 7, derivedKey: '0011', time: 10 },
    };

    expect(decodeBase64(encodeAltchaPayload(payload))).toEqual(payload);
  });

  it('keeps only canonical, scalar weak metadata', () => {
    const untrusted = {
      focus_count: 3.4,
      page_visible: false,
      raw_email: 'must-not-leave-browser',
      honeypot_filled: 'yes',
      input_count: Number.POSITIVE_INFINITY,
    } as unknown as WeakMetadata;

    expect(sanitizeMetadata(untrusted)).toEqual({ focus_count: 3, page_visible: false });
    expect(decodeBase64Url(encodeMetadata(untrusted)!)).toEqual({
      focus_count: 3,
      page_visible: false,
    });
  });
});
