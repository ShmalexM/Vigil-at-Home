// Sensors emit the shared @vigil/core SensorEvent. Helpers here keep the
// mapping code short under exactOptionalPropertyTypes.

import type { ProcessRef, SensorEvent } from '@vigil/core';

export type { ProcessRef, SensorEvent };

export type SensorEventSink = (event: SensorEvent) => void;

type OptionalKeys<T> = { [K in keyof T]: undefined extends T[K] ? K : never }[keyof T];
type RequiredKeys<T> = Exclude<keyof T, OptionalKeys<T>>;

/** The object with undefined-valued keys removed, typed so those keys become optional. */
export type Defined<T> = { [K in RequiredKeys<T>]: T[K] } & {
  [K in OptionalKeys<T>]?: Exclude<T[K], undefined>;
};

export function defined<T extends Record<string, unknown>>(o: T): Defined<T> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) if (v !== undefined) out[k] = v;
  return out as Defined<T>;
}

export function num(v: string | number | undefined): number | undefined {
  if (v === undefined || v === '') return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

/** pids and ppids: non-negative integers, or undefined. */
export function pidOf(v: string | number | undefined): number | undefined {
  const n = num(v);
  return n !== undefined && Number.isInteger(n) && n >= 0 ? n : undefined;
}

export function nonEmpty(v: string | undefined): string | undefined {
  return v === undefined || v === '' || v === '(null)' ? undefined : v;
}
