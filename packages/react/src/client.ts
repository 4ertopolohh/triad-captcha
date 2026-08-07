import type { Challenge } from 'altcha-lib';

import { encodeMetadata } from './encoding';
import { isAntibotErrorCode, TriadCaptchaError } from './errors';
import { solveAltchaChallenge } from './solver';
import type {
  AntibotErrorCode,
  ProtectedFetchContext,
  TriadCaptchaClient,
  TriadCaptchaClientOptions,
  WeakMetadata,
} from './types';

export const TRIADCAPTCHA_HEADERS = Object.freeze({
  action: 'X-TriadCAPTCHA-Action',
  metadata: 'X-TriadCAPTCHA-Metadata',
  proof: 'X-TriadCAPTCHA-Payload',
  siteKey: 'X-TriadCAPTCHA-Site-Key',
});

const DEFAULT_CHALLENGE_URL = '/api/triadcaptcha/challenge/';
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_JSON_RESPONSE_LENGTH = 65_536;
const MAX_PROOF_LENGTH = 32_768;
const ACTION_PATTERN = /^[a-z][a-z0-9._:-]{0,63}$/u;

interface PublicErrorData {
  code: AntibotErrorCode;
  retryAfter?: number;
}

interface NormalizedOptions {
  siteKey: string;
  challengeUrl: string;
  trustedOrigins: ReadonlySet<string>;
  timeoutMs: number;
  workers: number;
  fetch: typeof fetch;
  challengeHeaders?: HeadersInit;
  workerFactory?: TriadCaptchaClientOptions['workerFactory'];
  solver: NonNullable<TriadCaptchaClientOptions['solver']>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertAction(action: string): void {
  if (!ACTION_PATTERN.test(action)) {
    throw new TriadCaptchaError('ANTIBOT_CONFIGURATION_ERROR');
  }
}

function currentOrigin(): string {
  const origin = globalThis.location?.origin;
  if (!origin || origin === 'null') {
    throw new TriadCaptchaError('ANTIBOT_CONFIGURATION_ERROR');
  }
  return origin;
}

function resolveTrustedUrl(input: string | URL, trustedOrigins: ReadonlySet<string>): URL {
  let url: URL;
  try {
    url = new URL(input.toString(), currentOrigin());
  } catch (error) {
    throw new TriadCaptchaError('ANTIBOT_CONFIGURATION_ERROR', { cause: error });
  }
  if (
    (url.origin !== currentOrigin() && !trustedOrigins.has(url.origin)) ||
    !['http:', 'https:'].includes(url.protocol) ||
    url.username !== '' ||
    url.password !== ''
  ) {
    throw new TriadCaptchaError('ANTIBOT_CONFIGURATION_ERROR');
  }
  return url;
}

function inputUrl(input: RequestInfo | URL): string | URL {
  return input instanceof Request ? input.url : input;
}

function createBaseRequest(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  trustedOrigins: ReadonlySet<string>,
): Request {
  const url = resolveTrustedUrl(inputUrl(input), trustedOrigins);
  try {
    const request = input instanceof Request
      ? new Request(input, init)
      : new Request(url, init);
    // Do not let a redirect forward the public site key, metadata, or proof to
    // another origin. Django integrations should use canonical slash URLs.
    return new Request(request, { redirect: 'error' });
  } catch (error) {
    throw new TriadCaptchaError('ANTIBOT_INVALID_PAYLOAD', { cause: error });
  }
}

function withProtectionHeaders(
  baseRequest: Request,
  options: NormalizedOptions,
  action: string,
  encodedMetadata: string | undefined,
  proof: string | undefined,
): Request {
  const headers = new Headers(baseRequest.headers);
  headers.set(TRIADCAPTCHA_HEADERS.siteKey, options.siteKey);
  headers.set(TRIADCAPTCHA_HEADERS.action, action);
  if (encodedMetadata) {
    headers.set(TRIADCAPTCHA_HEADERS.metadata, encodedMetadata);
  } else {
    headers.delete(TRIADCAPTCHA_HEADERS.metadata);
  }
  if (proof) {
    headers.set(TRIADCAPTCHA_HEADERS.proof, proof);
  } else {
    // Never accept a caller-supplied proof: it may be stale or replayed.
    headers.delete(TRIADCAPTCHA_HEADERS.proof);
  }
  return new Request(baseRequest.clone(), { headers });
}

async function safeReadJson(response: Response): Promise<unknown> {
  try {
    const contentLength = Number(response.headers.get('Content-Length'));
    if (Number.isFinite(contentLength) && contentLength > MAX_JSON_RESPONSE_LENGTH) {
      return undefined;
    }
    const text = await response.clone().text();
    if (text.length === 0 || text.length > MAX_JSON_RESPONSE_LENGTH) {
      return undefined;
    }
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function parseRetryAfterValue(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) {
    return Math.ceil(value);
  }
  if (typeof value === 'string' && /^\d+(?:\.\d+)?$/u.test(value)) {
    return Math.ceil(Number(value));
  }
  return undefined;
}

function parseRetryAfterHeader(response: Response): number | undefined {
  const value = response.headers.get('Retry-After');
  if (!value) {
    return undefined;
  }
  const seconds = parseRetryAfterValue(value);
  if (seconds !== undefined) {
    return seconds;
  }
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? Math.max(0, Math.ceil((timestamp - Date.now()) / 1_000)) : undefined;
}

function parsePublicErrorPayload(payload: unknown): PublicErrorData | undefined {
  if (!isRecord(payload)) {
    return undefined;
  }
  const nested = isRecord(payload.error) ? payload.error : undefined;
  const codeValue = nested?.code ?? payload.code ??
    (typeof payload.error === 'string' ? payload.error : undefined);
  if (!isAntibotErrorCode(codeValue)) {
    return undefined;
  }
  const retryAfter = parseRetryAfterValue(nested?.retry_after ?? payload.retry_after);
  return retryAfter === undefined ? { code: codeValue } : { code: codeValue, retryAfter };
}

async function parsePublicError(response: Response): Promise<PublicErrorData | undefined> {
  const parsed = parsePublicErrorPayload(await safeReadJson(response));
  if (parsed) {
    if (parsed.retryAfter === undefined && parsed.code === 'ANTIBOT_RATE_LIMITED') {
      const headerRetryAfter = parseRetryAfterHeader(response);
      return headerRetryAfter === undefined
        ? parsed
        : { ...parsed, retryAfter: headerRetryAfter };
    }
    return parsed;
  }
  return undefined;
}

function toError(error: PublicErrorData, status: number): TriadCaptchaError {
  return new TriadCaptchaError(error.code, {
    status,
    ...(error.retryAfter === undefined ? {} : { retryAfter: error.retryAfter }),
  });
}

function extractChallenge(payload: unknown): Challenge {
  const candidate = isRecord(payload) && isRecord(payload.challenge)
    ? payload.challenge
    : payload;
  if (!isRecord(candidate) || !isRecord(candidate.parameters)) {
    throw new TriadCaptchaError('ANTIBOT_INVALID_PAYLOAD');
  }
  return candidate as unknown as Challenge;
}

function challengeRequestHeaders(options: NormalizedOptions, metadata: string | undefined): Headers {
  const headers = new Headers(options.challengeHeaders);
  headers.set('Accept', 'application/json');
  headers.set(TRIADCAPTCHA_HEADERS.siteKey, options.siteKey);
  headers.delete(TRIADCAPTCHA_HEADERS.proof);
  headers.delete(TRIADCAPTCHA_HEADERS.action);
  if (metadata) {
    headers.set(TRIADCAPTCHA_HEADERS.metadata, metadata);
  } else {
    headers.delete(TRIADCAPTCHA_HEADERS.metadata);
  }
  return headers;
}

async function fetchChallenge(
  options: NormalizedOptions,
  action: string,
  metadata: string | undefined,
  signal: AbortSignal,
): Promise<Challenge> {
  const url = resolveTrustedUrl(options.challengeUrl, options.trustedOrigins);
  url.searchParams.set('action', action);
  // A Request's signal can originate in another browser realm (for example an
  // iframe). Bridge it so the new Request always receives a local AbortSignal.
  const requestController = new AbortController();
  const abortRequest = () => requestController.abort(signal.reason);
  if (signal.aborted) {
    abortRequest();
  } else {
    signal.addEventListener('abort', abortRequest, { once: true });
  }
  const request = new Request(url, {
    cache: 'no-store',
    credentials: 'include',
    headers: challengeRequestHeaders(options, metadata),
    method: 'GET',
    redirect: 'error',
    signal: requestController.signal,
  });

  let response: Response;
  try {
    response = await options.fetch(request);
  } catch (error) {
    if (signal.aborted) {
      throw error;
    }
    throw new TriadCaptchaError('ANTIBOT_SERVICE_UNAVAILABLE', { cause: error });
  } finally {
    signal.removeEventListener('abort', abortRequest);
  }
  if (!response.ok) {
    const publicError = await parsePublicError(response);
    throw toError(publicError ?? { code: 'ANTIBOT_SERVICE_UNAVAILABLE' }, response.status);
  }
  return extractChallenge(await safeReadJson(response));
}

function hardwareWorkerCount(): number {
  const hardwareConcurrency = globalThis.navigator?.hardwareConcurrency ?? 2;
  return Math.min(4, Math.max(1, Math.floor(hardwareConcurrency)));
}

function normalizeOptions(options: TriadCaptchaClientOptions): NormalizedOptions {
  if (
    typeof options.siteKey !== 'string' ||
    options.siteKey.length === 0 ||
    options.siteKey.length > 256 ||
    !/^[A-Za-z0-9._:-]+$/u.test(options.siteKey)
  ) {
    throw new TriadCaptchaError('ANTIBOT_CONFIGURATION_ERROR');
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const workers = options.workers ?? hardwareWorkerCount();
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) {
    throw new TriadCaptchaError('ANTIBOT_CONFIGURATION_ERROR');
  }
  if (!Number.isSafeInteger(workers) || workers < 1 || workers > 16) {
    throw new TriadCaptchaError('ANTIBOT_CONFIGURATION_ERROR');
  }
  const globalFetch = globalThis.fetch;
  const fetchImplementation = options.fetch ?? (
    typeof globalFetch === 'function' ? globalFetch.bind(globalThis) : globalFetch
  );
  if (typeof fetchImplementation !== 'function') {
    throw new TriadCaptchaError('ANTIBOT_CONFIGURATION_ERROR');
  }
  const trustedOrigins = new Set<string>();
  for (const value of options.trustedOrigins ?? []) {
    let url: URL;
    try {
      url = new URL(value);
    } catch (error) {
      throw new TriadCaptchaError('ANTIBOT_CONFIGURATION_ERROR', { cause: error });
    }
    if (
      !['http:', 'https:'].includes(url.protocol) ||
      url.username !== '' ||
      url.password !== '' ||
      url.pathname !== '/' ||
      url.search !== '' ||
      url.hash !== '' ||
      value.includes('*')
    ) {
      throw new TriadCaptchaError('ANTIBOT_CONFIGURATION_ERROR');
    }
    trustedOrigins.add(url.origin);
  }
  return {
    siteKey: options.siteKey,
    challengeUrl: options.challengeUrl ?? DEFAULT_CHALLENGE_URL,
    trustedOrigins,
    timeoutMs,
    workers,
    fetch: fetchImplementation,
    solver: options.solver ?? solveAltchaChallenge,
    ...(options.challengeHeaders === undefined
      ? {}
      : { challengeHeaders: options.challengeHeaders }),
    ...(options.workerFactory === undefined ? {} : { workerFactory: options.workerFactory }),
  };
}

async function fetchWithStableError(
  options: NormalizedOptions,
  request: Request,
): Promise<Response> {
  try {
    return await options.fetch(request);
  } catch (error) {
    if (request.signal.aborted) {
      throw error;
    }
    throw new TriadCaptchaError('ANTIBOT_SERVICE_UNAVAILABLE', { cause: error });
  }
}

async function protectedFetchImpl(
  options: NormalizedOptions,
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  context: ProtectedFetchContext,
): Promise<Response> {
  assertAction(context.action);
  const baseRequest = createBaseRequest(input, init, options.trustedOrigins);
  const metadata = encodeMetadata(context.metadata);
  const initialRequest = withProtectionHeaders(
    baseRequest,
    options,
    context.action,
    metadata,
    undefined,
  );
  const initialResponse = await fetchWithStableError(options, initialRequest);
  if (initialResponse.ok) {
    return initialResponse;
  }

  const initialError = await parsePublicError(initialResponse);
  if (!initialError) {
    return initialResponse;
  }
  if (initialError.code !== 'ANTIBOT_CHALLENGE_REQUIRED') {
    throw toError(initialError, initialResponse.status);
  }

  const challenge = await fetchChallenge(
    options,
    context.action,
    metadata,
    baseRequest.signal,
  );
  const proof = await options.solver(challenge, {
    concurrency: options.workers,
    timeoutMs: options.timeoutMs,
    signal: baseRequest.signal,
    ...(options.workerFactory === undefined ? {} : { workerFactory: options.workerFactory }),
  });
  if (
    typeof proof !== 'string' ||
    proof.length === 0 ||
    proof.length > MAX_PROOF_LENGTH ||
    !/^[A-Za-z0-9+/]+={0,2}$/u.test(proof)
  ) {
    throw new TriadCaptchaError('ANTIBOT_INVALID_PAYLOAD');
  }

  const retryRequest = withProtectionHeaders(
    baseRequest,
    options,
    context.action,
    metadata,
    proof,
  );
  const retryResponse = await fetchWithStableError(options, retryRequest);
  if (retryResponse.ok) {
    return retryResponse;
  }
  const retryError = await parsePublicError(retryResponse);
  if (retryError) {
    throw toError(retryError, retryResponse.status);
  }
  return retryResponse;
}

export function createTriadCaptchaClient(
  clientOptions: TriadCaptchaClientOptions,
): TriadCaptchaClient {
  const options = normalizeOptions(clientOptions);
  return Object.freeze({
    protectedFetch(
      input: RequestInfo | URL,
      init: RequestInit | undefined,
      context: ProtectedFetchContext,
    ) {
      return protectedFetchImpl(options, input, init, context);
    },
  });
}

export type ProtectedFetch = TriadCaptchaClient['protectedFetch'];

export function createProtectedFetch(options: TriadCaptchaClientOptions): ProtectedFetch {
  return createTriadCaptchaClient(options).protectedFetch;
}

export function mergeWeakMetadata(
  collected: WeakMetadata,
  supplied: WeakMetadata | undefined,
): WeakMetadata {
  return supplied ? { ...collected, ...supplied } : collected;
}
