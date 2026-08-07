import { describe, expect, it, vi } from 'vitest';

import { createInteractionTracker } from '../src';

describe('interaction tracker', () => {
  it('collects counts and elapsed time without field values', () => {
    const now = vi.spyOn(performance, 'now');
    now.mockReturnValueOnce(100).mockReturnValueOnce(450);
    const tracker = createInteractionTracker();
    tracker.markFocus();
    tracker.markInput();
    tracker.markKeyboard();
    tracker.markPointer();

    expect(tracker.snapshot({ was_autofilled: false })).toMatchObject({
      form_fill_ms: 350,
      focus_count: 1,
      input_count: 1,
      keyboard_count: 1,
      pointer_count: 1,
      was_autofilled: false,
    });
    now.mockRestore();
  });

  it('resets counters', () => {
    const tracker = createInteractionTracker();
    tracker.markFocus();
    tracker.markInput();
    tracker.reset();

    expect(tracker.snapshot()).toMatchObject({ focus_count: 0, input_count: 0 });
  });
});
