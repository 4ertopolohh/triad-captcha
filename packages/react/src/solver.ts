import { solveChallengeWorkers, type Challenge } from 'altcha-lib';

import { encodeAltchaPayload } from './encoding';
import { TriadCaptchaError } from './errors';
import type { ProofOfWorkSolver, SolveOptions, WorkerFactory } from './types';

const SUPPORTED_ALGORITHMS = new Set([
  'PBKDF2/SHA-256',
  'PBKDF2/SHA-384',
  'PBKDF2/SHA-512',
  'SHA-256',
  'SHA-384',
  'SHA-512',
]);

export function createDefaultWorker(algorithm: string): Worker {
  if (!SUPPORTED_ALGORITHMS.has(algorithm)) {
    throw new TriadCaptchaError('ANTIBOT_INVALID_PAYLOAD');
  }
  if (typeof Worker === 'undefined') {
    throw new TriadCaptchaError('ANTIBOT_SERVICE_UNAVAILABLE');
  }
  return new Worker(new URL('./pow.worker.ts', import.meta.url), {
    name: 'triadcaptcha-pow',
    type: 'module',
  });
}

function createAbortError(): DOMException {
  return new DOMException('The operation was aborted.', 'AbortError');
}

function validateChallenge(challenge: Challenge): void {
  const parameters = challenge?.parameters;
  if (
    !parameters ||
    typeof challenge.signature !== 'string' ||
    challenge.signature.length === 0 ||
    typeof parameters.algorithm !== 'string' ||
    typeof parameters.nonce !== 'string' ||
    typeof parameters.salt !== 'string' ||
    typeof parameters.keyPrefix !== 'string' ||
    !Number.isSafeInteger(parameters.cost) ||
    parameters.cost <= 0 ||
    !Number.isSafeInteger(parameters.keyLength) ||
    parameters.keyLength <= 0
  ) {
    throw new TriadCaptchaError('ANTIBOT_INVALID_PAYLOAD');
  }
  if (parameters.expiresAt !== undefined && parameters.expiresAt <= Date.now() / 1_000) {
    throw new TriadCaptchaError('ANTIBOT_CHALLENGE_EXPIRED');
  }
}

function linkAbortSignal(signal: AbortSignal | undefined, controller: AbortController): () => void {
  if (!signal) {
    return () => undefined;
  }
  const abort = () => controller.abort(signal.reason);
  if (signal.aborted) {
    abort();
  } else {
    signal.addEventListener('abort', abort, { once: true });
  }
  return () => signal.removeEventListener('abort', abort);
}

export const solveAltchaChallenge: ProofOfWorkSolver = async (
  challenge: Challenge,
  options: SolveOptions,
): Promise<string> => {
  validateChallenge(challenge);
  if (options.signal?.aborted) {
    throw createAbortError();
  }

  const controller = new AbortController();
  const unlinkAbort = linkAbortSignal(options.signal, controller);
  const workerFactory: WorkerFactory = options.workerFactory ?? createDefaultWorker;

  try {
    const solution = await solveChallengeWorkers({
      challenge,
      concurrency: options.concurrency,
      controller,
      createWorker: workerFactory,
      timeout: options.timeoutMs,
    });
    if (controller.signal.aborted) {
      throw createAbortError();
    }
    if (!solution) {
      throw new TriadCaptchaError('ANTIBOT_SERVICE_UNAVAILABLE');
    }
    return encodeAltchaPayload({ challenge, solution });
  } catch (error) {
    if (controller.signal.aborted) {
      throw createAbortError();
    }
    if (error instanceof TriadCaptchaError) {
      throw error;
    }
    throw new TriadCaptchaError('ANTIBOT_SERVICE_UNAVAILABLE', { cause: error });
  } finally {
    unlinkAbort();
  }
};
