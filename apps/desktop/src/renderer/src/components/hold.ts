/** What started a hold: a pointer (by id) or a key (by name). */
export type HoldSource = { pointer: number } | { key: string };

export type HoldState = 'idle' | 'holding' | 'done';

function same(a: HoldSource, b: HoldSource): boolean {
  return 'pointer' in a ? 'pointer' in b && a.pointer === b.pointer : 'key' in b && a.key === b.key;
}

/**
 * The timing behind HoldButton, kept apart from React so it can be tested.
 * A hold remembers what started it: only that same pointer or key letting go
 * cancels it early, and anything that takes the hold away from the button
 * (focus leaving, the pointer leaving or being cancelled) aborts it.
 */
export class Hold {
  private state: HoldState = 'idle';
  private by: HoldSource | undefined;
  private timer: ReturnType<typeof setTimeout> | undefined;

  constructor(
    /** How long to hold, read when a hold starts. */
    public ms: number,
    private readonly onChange: (state: HoldState) => void,
    private readonly onConfirm: () => void,
  ) {}

  get current(): HoldState {
    return this.state;
  }

  /** A pointer or key went down on the button. Ignored unless idle. */
  press(by: HoldSource): void {
    if (this.state !== 'idle') return;
    this.by = by;
    this.set('holding');
    this.timer = setTimeout(() => {
      this.timer = undefined;
      this.by = undefined;
      this.set('done');
      this.onConfirm();
    }, this.ms);
  }

  /** A pointer or key came up: cancels only when it is the one holding. */
  release(by: HoldSource): void {
    if (this.by && same(this.by, by)) this.abort();
  }

  /** The pointer left the button: cancels a pointer hold, not a key hold. */
  pointerLeft(pointer: number): void {
    this.release({ pointer });
  }

  /** Cancels whatever is holding: focus left, the pointer was cancelled, unmount. */
  abort(): void {
    clearTimeout(this.timer);
    this.timer = undefined;
    this.by = undefined;
    if (this.state === 'holding') this.set('idle');
  }

  private set(state: HoldState): void {
    this.state = state;
    this.onChange(state);
  }
}
