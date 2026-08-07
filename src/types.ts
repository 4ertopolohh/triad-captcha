import type { Challenge, Solution } from 'altcha-lib';
import type {
  FocusEvent,
  FormEvent,
  KeyboardEvent,
  PointerEvent,
} from 'react';

export const ANTIBOT_ERROR_CODES = [
  'ANTIBOT_CHALLENGE_REQUIRED',
  'ANTIBOT_RATE_LIMITED',
  'ANTIBOT_BLOCKED',
  'ANTIBOT_INVALID_PAYLOAD',
  'ANTIBOT_CHALLENGE_EXPIRED',
  'ANTIBOT_CHALLENGE_REPLAYED',
  'ANTIBOT_SERVICE_UNAVAILABLE',
  'ANTIBOT_CONFIGURATION_ERROR',
] as const;

export type AntibotErrorCode = (typeof ANTIBOT_ERROR_CODES)[number];

/**
 * Deliberately weak, non-identifying browser signals. Do not put email,
 * telephone, passwords, tokens, or free-form field values in this object.
 */
export interface WeakMetadata {
  form_fill_ms?: number;
  focus_count?: number;
  input_count?: number;
  pointer_count?: number;
  keyboard_count?: number;
  page_visible?: boolean;
  honeypot_filled?: boolean;
  was_autofilled?: boolean;
}

export interface ProtectedFetchContext {
  action: string;
  metadata?: WeakMetadata;
}

export interface SolveOptions {
  concurrency: number;
  signal?: AbortSignal;
  timeoutMs: number;
  workerFactory?: WorkerFactory;
}

export type WorkerFactory = (algorithm: string) => Worker | Promise<Worker>;

export type ProofOfWorkSolver = (
  challenge: Challenge,
  options: SolveOptions,
) => Promise<string>;

export interface TriadCaptchaClientOptions {
  /** Public installation identifier. It is not a security secret. */
  siteKey: string;
  /** URL accepted by the same-origin/trusted-origin policy. */
  challengeUrl?: string;
  /**
   * Exact additional HTTP(S) origins trusted to receive TriadCAPTCHA headers.
   * Same-origin remains allowed automatically. Wildcards and URLs with paths,
   * credentials, queries, or fragments are rejected.
   */
  trustedOrigins?: readonly string[];
  /** Maximum PoW time. Defaults to 30 seconds. */
  timeoutMs?: number;
  /** Number of official ALTCHA workers. Defaults to 1..4 based on hardware. */
  workers?: number;
  /** Fetch override for tests or framework instrumentation. */
  fetch?: typeof fetch;
  /** Extra same-origin challenge request headers, for example a trace ID. */
  challengeHeaders?: HeadersInit;
  /** Custom worker factory for a private/custom ALTCHA algorithm. */
  workerFactory?: WorkerFactory;
  /** Advanced override, primarily useful for deterministic tests. */
  solver?: ProofOfWorkSolver;
}

export interface TriadCaptchaClient {
  protectedFetch(
    input: RequestInfo | URL,
    init: RequestInit | undefined,
    context: ProtectedFetchContext,
  ): Promise<Response>;
}

export interface AltchaPayload {
  challenge: Challenge;
  solution: Solution;
}

export interface ChallengeEnvelope {
  challenge: Challenge;
}

export interface InteractionTracker {
  markFocus(): void;
  markInput(): void;
  markPointer(): void;
  markKeyboard(): void;
  reset(): void;
  snapshot(extra?: WeakMetadata): WeakMetadata;
}

export interface InteractionProps {
  onFocusCapture(event?: FocusEvent<Element>): void;
  onInputCapture(event?: FormEvent<Element>): void;
  onKeyDownCapture(event?: KeyboardEvent<Element>): void;
  onPointerDownCapture(event?: PointerEvent<Element>): void;
}

export interface UseTriadCaptchaResult {
  protectedFetch(
    input: RequestInfo | URL,
    init: RequestInit | undefined,
    context: ProtectedFetchContext,
  ): Promise<Response>;
  isVerifying: boolean;
  error: unknown;
  resetError(): void;
  resetSignals(): void;
  getMetadata(extra?: WeakMetadata): WeakMetadata;
  interactionProps: InteractionProps;
}

export type { Challenge as AltchaChallenge, Solution as AltchaSolution };
