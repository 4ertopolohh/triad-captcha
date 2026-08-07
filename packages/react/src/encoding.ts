import type { AltchaPayload, WeakMetadata } from './types';

const MAX_METADATA_ENCODED_LENGTH = 2_048;
const NUMERIC_METADATA_KEYS = new Set<keyof WeakMetadata>([
  'form_fill_ms',
  'focus_count',
  'input_count',
  'pointer_count',
  'keyboard_count',
]);
const BOOLEAN_METADATA_KEYS = new Set<keyof WeakMetadata>([
  'page_visible',
  'honeypot_filled',
  'was_autofilled',
]);

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function encodeJsonBase64(value: unknown): string {
  return bytesToBase64(new TextEncoder().encode(JSON.stringify(value)));
}

export function encodeJsonBase64Url(value: unknown): string {
  return encodeJsonBase64(value)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '');
}

export function encodeAltchaPayload(payload: AltchaPayload): string {
  return encodeJsonBase64(payload);
}

export function sanitizeMetadata(metadata: WeakMetadata | undefined): WeakMetadata {
  if (!metadata) {
    return {};
  }

  const sanitized: Record<string, number | boolean> = {};
  for (const [key, value] of Object.entries(metadata)) {
    const typedKey = key as keyof WeakMetadata;
    if (
      NUMERIC_METADATA_KEYS.has(typedKey) &&
      typeof value === 'number' &&
      Number.isFinite(value) &&
      value >= 0
    ) {
      const maximum = typedKey === 'form_fill_ms' ? 3_600_000 : 1_000;
      sanitized[typedKey] = Math.min(Math.round(value), maximum);
    } else if (BOOLEAN_METADATA_KEYS.has(typedKey) && typeof value === 'boolean') {
      sanitized[typedKey] = value;
    }
  }
  return sanitized as WeakMetadata;
}

export function encodeMetadata(metadata: WeakMetadata | undefined): string | undefined {
  const sanitized = sanitizeMetadata(metadata);
  if (Object.keys(sanitized).length === 0) {
    return undefined;
  }
  const encoded = encodeJsonBase64Url(sanitized);
  return encoded.length <= MAX_METADATA_ENCODED_LENGTH ? encoded : undefined;
}
