import type { Action, ActionRecord, Alert, SensorEvent, Severity } from '@vigil/core';

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
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

const base = (p: string) => p.split('/').filter(Boolean).pop() ?? p;

/** One plain sentence for what an action does. */
export function describeAction(a: Action): string {
  switch (a.kind) {
    case 'process.suspend':
      return `Pause process ${a.pid}`;
    case 'process.resume':
      return `Resume process ${a.pid}`;
    case 'process.kill':
      return `Stop process ${a.pid}`;
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
  }
}

export function headline(a: Alert): string {
  if (a.containment === 'active') return 'Vigil blocked something';
  if (a.containment === 'released') return 'Released by you';
  return 'Vigil needs you';
}
