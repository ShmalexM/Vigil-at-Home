import type { ProcessInfo, SensorEvent } from "../src/types.js";

let seq = 0;
export const T0 = Date.UTC(2026, 8, 1);
export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;

export function proc(p: Partial<ProcessInfo> & { path: string }): ProcessInfo {
  return { pid: 4242, ppid: 500, args: [p.path], ...p };
}

export function ev(e: Partial<SensorEvent> & Pick<SensorEvent, "kind">): SensorEvent {
  seq++;
  return { id: `e${seq}`, ts: T0 + seq * 1000, source: "osquery", ...e };
}

export const chrome = proc({
  path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  signing: { status: "developer_id", teamId: "EQHXZ8M8AV", signingId: "com.google.Chrome" },
  sha256: "c".repeat(64),
});

export const unsignedStealer = proc({
  path: "/private/tmp/.helper",
  sha256: "a".repeat(64),
  signing: { status: "adhoc" },
  parentPath: "/bin/zsh",
});

export const osascriptTool = (args: string[], ppid = 777) =>
  proc({ path: "/usr/bin/osascript", args: ["osascript", ...args], ppid, signing: { status: "apple" }, parentPath: "/private/tmp/.helper" });

export const shell = (cmd: string, name = "bash") =>
  proc({ path: `/bin/${name}`, args: [name, "-c", cmd], signing: { status: "apple" }, parentPath: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal" });
