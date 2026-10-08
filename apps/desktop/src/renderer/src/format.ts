import type { HelperOutcome } from '../../shared/ipc';
import type { Action, ActionRecord, Alert, SensorEvent, Severity } from '@vigil/core';
import type { ResponseProvenance } from './decision';

export const severityLabel: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export function timeAgo(ts: number, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - ts) / 1000));
  if (s < 45) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.round(h / 24);
  return `${d} d ago`;
}

export function clock(ts: number): string {
  return new Date(ts).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

/** Time only, to the second, for the live feed. Adds the date when it isn't today. */
export function timeOfDay(ts: number, now = Date.now()): string {
  const d = new Date(ts);
  const time = d.toLocaleTimeString(undefined, {
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
  });
  if (d.toDateString() === new Date(now).toDateString()) return time;
  return `${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} ${time}`;
}

const base = (p: string) => p.split('/').filter(Boolean).pop() ?? p;

/** One plain sentence for what an action does. */
export function describeAction(a: Action): string {
  switch (a.kind) {
    case 'process.suspend':
      return `Pause ${proc(a)}`;
    case 'process.resume':
      return `Resume ${proc(a)}`;
    case 'process.kill':
      return `Stop ${proc(a)}`;
    case 'network.block':
      return `Block connections to ${a.address}${a.port ? `:${a.port}` : ''}`;
    case 'network.unblock':
      return `Allow connections to ${a.address}${a.port ? `:${a.port}` : ''}`;
    case 'file.quarantine':
      return `Quarantine ${base(a.path)}`;
    case 'file.restore':
      return 'Restore quarantined file';
    case 'santa.rule.set':
      return `${a.policy === 'allow' ? 'Always allow' : 'Always block'} this ${santaNoun(a.ruleType)}`;
    case 'santa.rule.remove':
      return `Remove the Santa rule for this ${santaNoun(a.ruleType)}`;
    case 'persistence.disable':
      return `Turn off startup item ${base(a.path)}`;
    case 'persistence.enable':
      return `Turn on startup item ${base(a.path)}`;
  }
}

/** A process by name when the action carries its path, else by process id. */
function proc(a: { pid: number; path?: string | undefined }): string {
  return a.path ? `${base(a.path)} (process ${a.pid})` : `process ${a.pid}`;
}

function santaNoun(t: string): string {
  return (
    {
      binary: 'program',
      certificate: 'certificate',
      signingid: 'signed app',
      teamid: 'developer',
      cdhash: 'program build',
    }[t] ?? t
  );
}

/** Past tense for the log. */
export function describeRecord(r: ActionRecord): string {
  const what = describeAction(r.action);
  switch (r.status) {
    case 'done':
      return what;
    case 'undone':
      return `${what} (undone)`;
    case 'pending':
      return `${what}…`;
    case 'denied':
      return `${what}: not allowed`;
    case 'failed':
      return `${what}: failed`;
  }
}

export function actorLabel(actor: ActionRecord['actor']): string {
  return { user: 'You', rule: 'Rule', ai: 'AI' }[actor];
}

export function describeEvent(e: SensorEvent): string {
  switch (e.kind) {
    case 'process.exec':
      return `Started ${base(e.process.path)}`;
    case 'process.exit':
      return `Exited ${base(e.process.path)}`;
    case 'file':
      return `${e.op[0]?.toUpperCase()}${e.op.slice(1)} ${base(e.path)}`;
    case 'network.connection':
      return `Connected to ${e.remoteHost ?? e.remoteAddress}${e.remotePort ? `:${e.remotePort}` : ''}`;
    case 'persistence':
      return `Startup item ${e.change}: ${base(e.path)}`;
    case 'santa.decision':
      return `Santa ${e.decision === 'block' ? 'blocked' : 'allowed'} ${base(e.process.path)}`;
    case 'network.listen':
      return `Listening on port ${e.localPort}`;
    case 'browser.extension':
      return `${e.browser} extension ${e.change}: ${e.name ?? e.extensionId}`;
    case 'system.alert':
      return {
        xprotect_detected: 'XProtect found malware',
        tcc_modified: 'Privacy permission changed',
        gatekeeper_override: 'Gatekeeper was overridden',
      }[e.subtype];
    case 'agent.tool_request':
      // `#socket` is Vigil's own stand-in, on the alert it raises when its agent socket is taken.
      if (e.tool === '#socket') return 'Another program took Vigil’s agent socket';
      return `${{ 'claude-code': 'Claude Code' }[e.agent.host]} asked to use ${e.tool}`;
  }
}

/**
 * `response`: what Vigil's actions on this alert really did (responseProvenance).
 * Only an all-real response says "blocked"; one an older build recorded
 * without saying is never claimed as real.
 */
export function headline(a: Alert, response: ResponseProvenance | undefined): string {
  if (a.containment === 'active') {
    switch (response) {
      case 'real':
        return 'Vigil blocked something';
      case 'simulated':
        return 'Vigil would have blocked this';
      case 'mixed':
        return 'Vigil blocked part of this; the rest was only simulated';
      default:
        return 'Vigil acted on this';
    }
  }
  if (a.containment === 'released') return 'Released by you';
  return 'Vigil needs you';
}

/** "Seen 3 times in 4 min" for an alert that folded in identical repeats, else undefined. */
export function seenTimes(a: Alert): string | undefined {
  const r = a.repeats;
  if (!r || r.count < 2) return undefined;
  const min = Math.max(1, Math.round((r.lastAt - a.createdAt) / 60_000));
  return `Seen ${r.count} times in ${min} min`;
}

/** What to say when the user asked to release an alert and the release didn't go through. */
export function releaseFailed(a: Alert): string {
  return a.containment === 'active'
    ? 'Couldn’t release it, so it’s still blocked and still needs you.'
    : 'Couldn’t finish releasing it, so it still needs you.';
}

/** Shown when a rule change was cancelled at the password, instead of the change. */
export const PASSWORD_CANCELLED = 'Not changed: the password was cancelled';

/** Added to a change's toast when the helper didn't take it yet. */
export function helperNote(helper: HelperOutcome): string {
  return helper === 'unavailable'
    ? ' The background helper isn’t connected, so it picks this up when it reconnects.'
    : '';
}
