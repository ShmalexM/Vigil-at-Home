import { describe, expect, it } from "vitest";
import { DetectionEngine } from "../src/engine.js";
import type { RuleInput } from "../src/rules/schema.js";
import { memoryStores } from "../src/state/stores.js";
import { chrome, DAY, ev, proc, T0 } from "./fixtures.js";

const base: Omit<RuleInput, "id" | "condition"> = {
  title: "Test rule",
  kinds: ["process_exec"],
  severity: "high",
  action: "suspend",
  reasons: ["{{process.name}} matched"],
};
const evil = proc({ path: "/Users/alex/Downloads/evil", sha256: "e".repeat(64), signing: { status: "unsigned" } });
const isEvil: RuleInput["condition"] = { field: "process.name", op: "eq", value: "evil" };

describe("stages", () => {
  it("shadow records only, alert caps at alert, enforce acts", () => {
    for (const [stage, want] of [
      ["shadow", "record"],
      ["alert", "alert"],
      ["enforce", "suspend"],
    ] as const) {
      const eng = new DetectionEngine([{ ...base, id: "r-test", stage, condition: isEvil }], memoryStores());
      const [d] = eng.evaluate(ev({ kind: "process_exec", process: evil }));
      expect(d?.action).toBe(want);
      expect(d?.requestedAction).toBe("suspend");
      expect(d?.stage).toBe(stage);
      if (stage !== "enforce") expect(d?.downgrades.length).toBeGreaterThan(0);
    }
  });
  it("rules default to shadow", () => {
    const eng = new DetectionEngine([{ ...base, id: "r-test", condition: isEvil }], memoryStores());
    expect(eng.evaluate(ev({ kind: "process_exec", process: evil }))[0]?.action).toBe("record");
  });
  it("only indexes rules for their event kinds", () => {
    const eng = new DetectionEngine([{ ...base, id: "r-test", stage: "enforce", condition: isEvil }], memoryStores());
    expect(eng.evaluate(ev({ kind: "file_open", process: evil, file: { path: "/x" } }))).toEqual([]);
  });
});

describe("safety floor", () => {
  const any: RuleInput = { ...base, id: "r-any", stage: "enforce", action: "block", condition: { field: "process.path", op: "exists" } };
  const run = (p: ReturnType<typeof proc>, cfg = {}) =>
    new DetectionEngine([any], memoryStores(), cfg).evaluate(ev({ kind: "process_exec", process: p }))[0]!;

  it("never pauses or kills Apple services", () => {
    const d = run(proc({ path: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", signing: { status: "apple" } }));
    expect(d.action).toBe("alert");
    expect(d.downgrades.join()).toMatch(/part of macOS/);
    expect(run(proc({ path: "/usr/libexec/xpcproxy", signing: { status: "apple" } })).action).toBe("alert");
    expect(run(proc({ path: "/sbin/launchd", pid: 1 })).action).toBe("alert");
  });
  it("may act on an Apple CLI tool started by something else, not one started by launchd", () => {
    expect(run(proc({ path: "/usr/bin/osascript", ppid: 900, signing: { status: "apple" } })).action).toBe("block");
    expect(run(proc({ path: "/usr/bin/osascript", ppid: 1, signing: { status: "apple" } })).action).toBe("alert");
  });
  it("never acts on Vigil itself or user-protected paths", () => {
    const cfg = { safety: { selfPaths: ["/Applications/Vigil.app"], protectedPathGlobs: ["/opt/work/**"] } };
    expect(run(proc({ path: "/Applications/Vigil.app/Contents/MacOS/Vigil" }), cfg).action).toBe("alert");
    expect(run(proc({ path: "/opt/work/tool" }), cfg).action).toBe("alert");
    expect(run(proc({ path: "/opt/other/tool" }), cfg).action).toBe("block");
  });
  it("never firewalls loopback or link-local addresses", () => {
    const net: RuleInput = { ...any, id: "r-net", kinds: ["network_connect"], target: "network", condition: { field: "network.remotePort", op: "eq", value: 4444 } };
    const eng = new DetectionEngine([net], memoryStores());
    const mk = (addr: string) => eng.evaluate(ev({ kind: "network_connect", process: chrome, network: { remoteAddress: addr, remotePort: 4444 } }))[0]!;
    expect(mk("127.0.0.1").action).toBe("alert");
    expect(mk("169.254.10.10").action).toBe("alert");
    expect(mk("203.0.113.9").action).toBe("block");
  });
});

describe("first seen and learning", () => {
  const rule: RuleInput = { ...base, id: "r-new", stage: "alert", action: "alert", condition: { firstSeen: { key: ["process.path"] } } };

  it("fires once per new key and learns after evaluating", () => {
    const eng = new DetectionEngine([rule, { ...rule, id: "r-new2" }], memoryStores());
    const a = eng.evaluate(ev({ kind: "process_exec", process: evil }));
    expect(a.map((d) => d.ruleId)).toEqual(["r-new", "r-new2"]);
    expect(eng.evaluate(ev({ kind: "process_exec", process: evil }))).toEqual([]);
  });
  it("keeps baselines separate per event kind", () => {
    const net: RuleInput = { ...rule, id: "r-net", kinds: ["network_connect"] };
    const eng = new DetectionEngine([rule, net], memoryStores());
    eng.evaluate(ev({ kind: "process_exec", process: evil }));
    expect(eng.evaluate(ev({ kind: "network_connect", process: evil, network: { remoteAddress: "203.0.113.1" } }))).toHaveLength(1);
  });
  it("only records during the learning period", () => {
    const eng = new DetectionEngine([rule], memoryStores(), { learningUntil: T0 + 7 * DAY });
    const d = eng.evaluate(ev({ kind: "process_exec", process: evil }))[0]!;
    expect(d.action).toBe("record");
    expect(d.downgrades.join()).toMatch(/learning/);
  });
});

describe("dedupe, thresholds, exceptions, lists", () => {
  it("pops up once per subject per window", () => {
    const eng = new DetectionEngine([{ ...base, id: "r-a", stage: "alert", action: "alert", condition: isEvil }], memoryStores());
    const first = eng.evaluate(ev({ kind: "process_exec", process: evil }))[0]!;
    const second = eng.evaluate(ev({ kind: "process_exec", process: evil }))[0]!;
    expect(first.action).toBe("alert");
    expect(second.deduped).toBe(true);
    expect(second.action).toBe("record");
  });
  it("keeps enforcing on duplicates (a known-bad program is killed every time)", () => {
    const eng = new DetectionEngine([{ ...base, id: "r-b", stage: "enforce", action: "block", condition: isEvil }], memoryStores());
    eng.evaluate(ev({ kind: "process_exec", process: evil }));
    const again = eng.evaluate(ev({ kind: "process_exec", process: evil }))[0]!;
    expect(again.deduped).toBe(true);
    expect(again.action).toBe("block");
  });
  it("fires a threshold rule once per burst", () => {
    const eng = new DetectionEngine(
      [{ ...base, id: "r-t", kinds: ["file_open"], stage: "alert", action: "alert", condition: isEvil, threshold: { count: 3, withinSec: 60, groupBy: ["process.pid"] } }],
      memoryStores(),
    );
    const fire = () => eng.evaluate(ev({ kind: "file_open", process: evil, file: { path: "/x" } })).length;
    expect([fire(), fire(), fire(), fire(), fire(), fire()]).toEqual([0, 0, 1, 0, 0, 1]);
  });
  it("respects user exceptions and rule exclusions", () => {
    const stores = memoryStores();
    const eng = new DetectionEngine(
      [
        { ...base, id: "r-x", stage: "alert", condition: isEvil },
        { ...base, id: "r-y", stage: "alert", condition: isEvil, exclusions: [{ field: "process.sha256", op: "eq", value: "e".repeat(64) }] },
      ],
      stores,
    );
    stores.exceptions.add({ id: "x1", ruleId: "r-x", field: "process.path", value: "/users/alex/downloads/EVIL", createdAt: 0 });
    expect(eng.evaluate(ev({ kind: "process_exec", process: evil }))).toEqual([]);
  });
  it("matches lists by exact value, subnet and parent domain", () => {
    const stores = memoryStores();
    stores.lists.replace("bad", ["evil.test", "198.51.100.0/24", "# comment", "1.2.3.4"], { source: "t", updatedAt: 0 });
    const eng = new DetectionEngine(
      [{ ...base, id: "r-l", kinds: ["network_connect"], target: "network", stage: "enforce", action: "block", condition: { any: [{ inList: { list: "bad", field: "network.domain" } }, { inList: { list: "bad", field: "network.remoteAddress" } }] } }],
      stores,
    );
    const hit = (network: object) => eng.evaluate(ev({ kind: "network_connect", process: chrome, network })).length;
    expect(hit({ domain: "cdn.evil.test", remoteAddress: "203.0.113.5" })).toBe(1);
    expect(hit({ domain: "notevil.test", remoteAddress: "203.0.113.6" })).toBe(0);
    expect(hit({ remoteAddress: "198.51.100.77" })).toBe(1);
    expect(hit({ remoteAddress: "1.2.3.4" })).toBe(1);
    expect(stores.lists.size("bad")).toBe(3);
  });
  it("suggests a Santa rule from the configured field", () => {
    const eng = new DetectionEngine([{ ...base, id: "r-s", stage: "enforce", condition: isEvil, santa: { ruleType: "BINARY", from: "process.sha256" } }], memoryStores());
    expect(eng.evaluate(ev({ kind: "process_exec", process: evil }))[0]!.santaSuggestion).toEqual({
      policy: "BLOCKLIST", ruleType: "BINARY", identifier: "e".repeat(64), customMsg: "Test rule",
    });
  });
  it("rejects bad rule sets before changing anything", () => {
    const eng = new DetectionEngine([{ ...base, id: "r-ok", condition: isEvil }], memoryStores());
    expect(() => eng.loadRules([{ ...base, id: "r-bad", condition: { field: "process.path", op: "regex", value: "(a+)+" } }])).toThrow(/nested/);
    expect(() => eng.loadRules([{ ...base, id: "r-d", condition: isEvil }, { ...base, id: "r-d", condition: isEvil }])).toThrow(/duplicate/);
    expect(eng.getRule("r-ok")).toBeDefined();
  });
});
