import { solveChallengeWorkers, type Challenge } from 'altcha-lib';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { solveAltchaChallenge } from '../src';

vi.mock('altcha-lib', async (importOriginal) => {
  const actual = await importOriginal<typeof import('altcha-lib')>();
  return { ...actual, solveChallengeWorkers: vi.fn() };
});

const validChallenge: Challenge = {
  parameters: {
    algorithm: 'PBKDF2/SHA-256',
    cost: 5_000,
    expiresAt: Math.floor(Date.now() / 1_000) + 60,
    keyLength: 32,
    keyPrefix: '00',
    nonce: '0011',
    salt: '2233',
  },
  signature: 'signed',
};

describe('ALTCHA solver', () => {
  beforeEach(() => vi.mocked(solveChallengeWorkers).mockReset());

  it('uses the official worker orchestrator and returns an encoded payload', async () => {
    vi.mocked(solveChallengeWorkers).mockResolvedValue({
      counter: 9,
      derivedKey: '001122',
      time: 5,
    });
    const workerFactory = vi.fn();

    const encoded = await solveAltchaChallenge(validChallenge, {
      concurrency: 2,
      timeoutMs: 1_000,
      workerFactory,
    });
    const decoded = JSON.parse(atob(encoded)) as Record<string, unknown>;

    expect(decoded).toEqual({
      challenge: validChallenge,
      solution: { counter: 9, derivedKey: '001122', time: 5 },
    });
    expect(solveChallengeWorkers).toHaveBeenCalledWith(
      expect.objectContaining({ challenge: validChallenge, concurrency: 2, timeout: 1_000 }),
    );
  });

  it('rejects unsigned and expired challenges before starting work', async () => {
    await expect(
      solveAltchaChallenge({ parameters: validChallenge.parameters }, {
        concurrency: 1,
        timeoutMs: 1_000,
      }),
    ).rejects.toMatchObject({ code: 'ANTIBOT_INVALID_PAYLOAD' });

    await expect(
      solveAltchaChallenge({
        ...validChallenge,
        parameters: { ...validChallenge.parameters, expiresAt: 1 },
      }, {
        concurrency: 1,
        timeoutMs: 1_000,
      }),
    ).rejects.toMatchObject({ code: 'ANTIBOT_CHALLENGE_EXPIRED' });
    expect(solveChallengeWorkers).not.toHaveBeenCalled();
  });

  it('maps a worker timeout to service unavailable', async () => {
    vi.mocked(solveChallengeWorkers).mockResolvedValue(null);
    await expect(
      solveAltchaChallenge(validChallenge, { concurrency: 1, timeoutMs: 1_000 }),
    ).rejects.toMatchObject({ code: 'ANTIBOT_SERVICE_UNAVAILABLE' });
  });
});
