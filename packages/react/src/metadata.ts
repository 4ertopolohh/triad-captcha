import type { InteractionTracker, WeakMetadata } from './types';

function monotonicNow(): number {
  return typeof performance === 'undefined' ? Date.now() : performance.now();
}

function boundedIncrement(value: number): number {
  return Math.min(value + 1, 10_000);
}

export function createInteractionTracker(): InteractionTracker {
  let startedAt = monotonicNow();
  let focusCount = 0;
  let inputCount = 0;
  let pointerCount = 0;
  let keyboardCount = 0;

  return {
    markFocus() {
      focusCount = boundedIncrement(focusCount);
    },
    markInput() {
      inputCount = boundedIncrement(inputCount);
    },
    markPointer() {
      pointerCount = boundedIncrement(pointerCount);
    },
    markKeyboard() {
      keyboardCount = boundedIncrement(keyboardCount);
    },
    reset() {
      startedAt = monotonicNow();
      focusCount = 0;
      inputCount = 0;
      pointerCount = 0;
      keyboardCount = 0;
    },
    snapshot(extra = {}) {
      const base: WeakMetadata = {
        form_fill_ms: Math.max(0, Math.round(monotonicNow() - startedAt)),
        focus_count: focusCount,
        input_count: inputCount,
        pointer_count: pointerCount,
        keyboard_count: keyboardCount,
        page_visible:
          typeof document === 'undefined' ? true : document.visibilityState !== 'hidden',
      };
      return { ...base, ...extra };
    },
  };
}
