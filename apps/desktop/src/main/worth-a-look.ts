import type { Alert, Rule, SensorEvent } from '@vigil/core';
import type { EventLabel } from '../shared/ipc.js';
import type { AlertService } from './alerts.js';
import { labelKey } from './label-filter.js';

/**
 * Turns the labeller's strongest catches into quiet "worth a look" alerts.
 *
 *   event no rule matched ─► labeller: suspicious, score ≥ 0.6 ─► alert in Noticed
 *                                    │                              (low, silent, no actions)
 *                                    └─► daily rule review (flagged events) ─► rule suggestions
 *
 * The AI only labels: these alerts run nothing, never pop up and never count
 * toward "Needs you". The user can look, answer, or clear them with "Those
 * were me". The local model's hints carry score 0, so only a scored
 * classifier (Jev, or Haiku on an API key) can raise one.
 */
export const WORTH_A_LOOK_RULE: Rule = {
  id: 'vigil.worth-a-look',
  version: 1,
  name: 'Worth a look',
  description:
    "Vigil's AI labeller found this suspicious, though no rule matched it. Nothing was blocked or changed; it is only a suggestion to take a look.",
  origin: 'builtin',
  mode: 'alert',
  severity: 'low',
  fidelity: 'low',
  eventKinds: ['process.exec'],
  condition: { field: 'process.path', op: 'eq', value: '' },
  response: [],
  exclusions: [],
  reasons: [],
  tags: [],
  createdAt: 0,
  updatedAt: 0,
};

/** How sure the labeller must be. Jev's scores on suspicious events start around here. */
export const WORTH_A_LOOK_MIN_SCORE = 0.6;
/** Even a noisy day adds only a few. */
export const WORTH_A_LOOK_PER_DAY = 5;
const DAY = 24 * 60 * 60 * 1000;

export class WorthALook {
  private raisedAt: number[] = [];
  private readonly lastByKey = new Map<string, number>();

  constructor(
    private readonly alerts: Pick<AlertService, 'raise'>,
    private readonly now: () => number = Date.now,
  ) {}

  /** Raise an alert for this label when it is strong enough and not a repeat. */
  async consider(event: SensorEvent, label: EventLabel): Promise<Alert | undefined> {
    if (label.label !== 'suspicious' || label.score < WORTH_A_LOOK_MIN_SCORE) return undefined;
    const at = this.now();
    const key = labelKey(event)?.key ?? event.id;
    const last = this.lastByKey.get(key);
    if (last !== undefined && at - last < DAY) return undefined;
    this.raisedAt = this.raisedAt.filter((t) => at - t < DAY);
    if (this.raisedAt.length >= WORTH_A_LOOK_PER_DAY) return undefined;
    this.raisedAt.push(at);
    this.lastByKey.set(key, at);
    if (this.lastByKey.size > 1000) this.lastByKey.delete(this.lastByKey.keys().next().value!);

    const subject = subjectOf(event);
    const by = label.by === 'jev' ? 'Jev' : 'an AI model';
    const reason = label.reason.trim();
    const why = reason && !/[.!?]$/.test(reason) ? `${reason}.` : reason;
    return this.alerts.raise({
      rule: WORTH_A_LOOK_RULE,
      events: [event],
      actions: [],
      title: `Worth a look: ${subject.label}`,
      summary: `${why ? `${why} ` : ''}No rule matched this and nothing was blocked. Labelled by ${by}.`,
      subject,
    });
  }
}

function subjectOf(e: SensorEvent): NonNullable<Alert['subject']> {
  const proc = 'process' in e ? e.process : undefined;
  const name = (p: string) => p.slice(p.lastIndexOf('/') + 1) || p;
  switch (e.kind) {
    case 'network.connection': {
      const to = e.remoteHost ?? e.remoteAddress;
      return { kind: 'network', label: proc ? `${name(proc.path)} → ${to}` : to };
    }
    case 'file':
      return { kind: 'file', label: name(e.path), path: e.path };
    case 'persistence':
      return { kind: 'persistence', label: e.label ?? name(e.path), path: e.path };
    default:
      return proc
        ? { kind: 'process', label: name(proc.path), path: proc.path }
        : { kind: 'process', label: e.kind };
  }
}
