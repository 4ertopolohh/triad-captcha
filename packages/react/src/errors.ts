import { ANTIBOT_ERROR_CODES, type AntibotErrorCode } from './types';

const errorCodeSet = new Set<string>(ANTIBOT_ERROR_CODES);

export interface TriadCaptchaErrorOptions {
  status?: number;
  retryAfter?: number;
  cause?: unknown;
}

export class TriadCaptchaError extends Error {
  readonly code: AntibotErrorCode;
  readonly status: number;
  readonly retryAfter?: number;

  constructor(code: AntibotErrorCode, options: TriadCaptchaErrorOptions = {}) {
    super(code, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'TriadCaptchaError';
    this.code = code;
    this.status = options.status ?? 0;
    if (options.retryAfter !== undefined) {
      this.retryAfter = options.retryAfter;
    }
  }
}

export function isAntibotErrorCode(value: unknown): value is AntibotErrorCode {
  return typeof value === 'string' && errorCodeSet.has(value);
}

export function isTriadCaptchaError(error: unknown): error is TriadCaptchaError {
  return error instanceof TriadCaptchaError;
}
