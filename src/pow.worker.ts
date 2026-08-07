/// <reference lib="webworker" />

import { solveChallenge, type Challenge } from 'altcha-lib';
import { deriveKey as derivePbkdf2Key } from 'altcha-lib/algorithms/web/pbkdf2';
import { deriveKey as deriveShaKey } from 'altcha-lib/algorithms/web/sha';

interface WorkMessage {
  type: 'work';
  challenge: Challenge;
  counterMode?: 'uint32' | 'string';
  counterStart: number;
  counterStep: number;
  timeout?: number;
}

interface AbortMessage {
  type: 'abort';
}

type WorkerMessage = WorkMessage | AbortMessage;

const workerScope = self as DedicatedWorkerGlobalScope;
let activeController: AbortController | undefined;

function selectDeriveKey(algorithm: string) {
  if (algorithm.startsWith('PBKDF2/')) {
    return derivePbkdf2Key;
  }
  if (/^SHA-(256|384|512)$/u.test(algorithm)) {
    return deriveShaKey;
  }
  throw new Error('Unsupported ALTCHA algorithm');
}

workerScope.addEventListener('message', (event: MessageEvent<WorkerMessage>) => {
  const message = event.data;
  if (message.type === 'abort') {
    activeController?.abort();
    return;
  }

  const controller = new AbortController();
  activeController?.abort();
  activeController = controller;

  void solveChallenge({
    challenge: message.challenge,
    deriveKey: selectDeriveKey(message.challenge.parameters.algorithm),
    controller,
    counterStart: message.counterStart,
    counterStep: message.counterStep,
    ...(message.counterMode === undefined ? {} : { counterMode: message.counterMode }),
    ...(message.timeout === undefined ? {} : { timeout: message.timeout }),
  })
    .then((solution) => {
      workerScope.postMessage(solution);
    })
    .catch(() => {
      // Detailed errors can reveal implementation data. The main thread maps this
      // stable marker to ANTIBOT_SERVICE_UNAVAILABLE.
      workerScope.postMessage({ error: 'Proof-of-work failed' });
    })
    .finally(() => {
      if (activeController === controller) {
        activeController = undefined;
      }
    });
});

export {};
