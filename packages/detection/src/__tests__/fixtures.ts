import type { DetectionEvent, DetectionProcessRef } from '../types.js';

let seq = 0;
export const T0 = Date.UTC(2026, 8, 1);
export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;

export function proc(p: Partial<DetectionProcessRef> & { path: string }): DetectionProcessRef {
  return { pid: 4242, ppid: 500, args: [p.path], ...p };
}

type Draft<E> = E extends DetectionEvent
  ? Omit<E, 'id' | 'ts' | 'source'> & Partial<Pick<E, 'id' | 'ts' | 'source'>>
  : never;

/** Build an event; ids and timestamps advance by one second per call. */
export function ev(e: Draft<DetectionEvent>): DetectionEvent {
  seq++;
  return { id: `e${seq}`, ts: T0 + seq * 1000, source: 'test', ...e } as DetectionEvent;
}

export const exec = (process: DetectionProcessRef) => ev({ kind: 'process.exec', process });
export const fileOpen = (process: DetectionProcessRef, path: string) =>
  ev({ kind: 'file', op: 'open', path, process });
export const connect = (process: DetectionProcessRef, remoteAddress: string, remoteHost?: string) =>
  ev({
    kind: 'network.connection',
    direction: 'outbound',
    protocol: 'tcp',
    remoteAddress,
    remotePort: 443,
    process,
    ...(remoteHost ? { remoteHost } : {}),
  });

export const chrome = proc({
  path: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  signing: 'developer_id',
  teamId: 'EQHXZ8M8AV',
  signingId: 'com.google.Chrome',
  sha256: 'c'.repeat(64),
});

export const unsignedStealer = proc({
  path: '/private/tmp/.helper',
  sha256: 'a'.repeat(64),
  signing: 'adhoc',
  parentPath: '/bin/zsh',
});

export const osascriptTool = (args: string[], ppid = 777) =>
  proc({
    path: '/usr/bin/osascript',
    args: ['osascript', ...args],
    ppid,
    signing: 'apple',
    parentPath: '/private/tmp/.helper',
  });

export const shell = (cmd: string, name = 'bash') =>
  proc({
    path: `/bin/${name}`,
    args: [name, '-c', cmd],
    signing: 'apple',
    parentPath: '/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal',
  });

/** A minimal valid rule for engine tests. */
export function testRule(r: Record<string, unknown> & { id: string; condition: unknown }) {
  return {
    version: 1,
    name: 'Test rule',
    description: '',
    origin: 'user',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    createdAt: T0,
    updatedAt: T0,
    reasons: ['{{process.name}} matched'],
    ...r,
  } as never;
}
