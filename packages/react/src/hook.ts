import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { createTriadCaptchaClient, mergeWeakMetadata } from './client';
import { createInteractionTracker } from './metadata';
import type {
  InteractionProps,
  InteractionTracker,
  ProtectedFetchContext,
  TriadCaptchaClientOptions,
  UseTriadCaptchaResult,
  WeakMetadata,
} from './types';

export function useTriadCaptcha(options: TriadCaptchaClientOptions): UseTriadCaptchaResult {
  const optionsRef = useRef(options);
  optionsRef.current = options;

  const trackerRef = useRef<InteractionTracker | null>(null);
  if (trackerRef.current === null) {
    trackerRef.current = createInteractionTracker();
  }
  const tracker = trackerRef.current;

  const mountedRef = useRef(true);
  const [pending, setPending] = useState(0);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const getMetadata = useCallback(
    (extra?: WeakMetadata) => tracker.snapshot(extra),
    [tracker],
  );

  const protectedFetch = useCallback(
    async (
      input: RequestInfo | URL,
      init: RequestInit | undefined,
      context: ProtectedFetchContext,
    ): Promise<Response> => {
      if (mountedRef.current) {
        setPending((value) => value + 1);
        setError(null);
      }
      try {
        const client = createTriadCaptchaClient(optionsRef.current);
        return await client.protectedFetch(input, init, {
          ...context,
          metadata: mergeWeakMetadata(tracker.snapshot(), context.metadata),
        });
      } catch (caught) {
        if (mountedRef.current) {
          setError(caught);
        }
        throw caught;
      } finally {
        if (mountedRef.current) {
          setPending((value) => Math.max(0, value - 1));
        }
      }
    },
    [tracker],
  );

  const interactionProps = useMemo<InteractionProps>(
    () => ({
      onFocusCapture: () => tracker.markFocus(),
      onInputCapture: () => tracker.markInput(),
      onKeyDownCapture: () => tracker.markKeyboard(),
      onPointerDownCapture: () => tracker.markPointer(),
    }),
    [tracker],
  );

  return {
    protectedFetch,
    isVerifying: pending > 0,
    error,
    resetError: useCallback(() => setError(null), []),
    resetSignals: useCallback(() => tracker.reset(), [tracker]),
    getMetadata,
    interactionProps,
  };
}
