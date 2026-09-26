import { describe, expect, it } from "vitest";
import { DetectionEngine } from "../src/engine.js";
import { Feedback } from "../src/feedback.js";
import { macosCoreRules } from "../src/packs/macos-core.js";
import type { RuleInput } from "../src/rules/schema.js";
import { memoryStores } from "../src/state/stores.js";
import { userOrigin } from "../src/user.js";
import { ev, proc, T0 } from "./fixtures.js";

const me = userOrigin("test");
const noisy: RuleInput = {
  id: "noisy-rule",
  title: "Noisy",
  kinds: ["process_exec"],
  severity: "medium",
  action: "suspend",
  stage: "enforce",
  condition: { field: "process.path", op: "startsWith", value: "/opt/" },
  reasons: ["{{process.name}} ran"],
  dedupe: { key: ["process.path"], windowSec: 0 },
};
const tool = (n: number) => proc({ path: `/opt/tools/t${n}`, sha256: String(n).repeat(64).slice(0, 64) });

describe("user verdicts", () => {
  it("marking a detection safe adds a narrow exception so it stops firing", () => {
    const eng = new DetectionEngine([noisy], memoryStores());
    const fb = new Feedback(eng, undefined, () => T0);
    const e = ev({ kind: "process_exec", process: tool(1) });
    const d = eng.evaluate(e)[0]!;
    const res = fb.recordVerdict(d, "benign", me, { event: e });
    expect(res.exception).toMatchObject({ ruleId: "noisy-rule", field: "process.sha256" });
    expect(eng.evaluate(ev({ kind: "process_exec", process: tool(1) }))).toEqual([]);
    // A different program still fires.
    expect(eng.evaluate(ev({ kind: "process_exec", process: tool(2) }))).toHaveLength(1);
  });

  it("demotes a rule one stage after repeated false positives, never promotes", () => {
    const eng = new DetectionEngine([noisy], memoryStores());
    const fb = new Feedback(eng, undefined, () => T0);
    const results = [1, 2, 3].map((n) => {
      const e = ev({ kind: "process_exec", process: tool(n) });
      return fb.recordVerdict(eng.evaluate(e)[0]!, "benign", me, { event: e });
    });
    expect(results[1]!.demoted).toBeUndefined();
    expect(results[2]!.demoted).toMatchObject({ from: "enforce", to: "alert" });
    expect(eng.stageOf(eng.getRule("noisy-rule")!)).toBe("alert");
    expect(eng.evaluate(ev({ kind: "process_exec", process: tool(9) }))[0]!.action).toBe("alert");
  });

  it("confirming a threat blocks that program from then on and returns a Santa rule", () => {
    const stores = memoryStores();
    const eng = new DetectionEngine(macosCoreRules, stores);
    const bad = proc({ path: "/private/tmp/x", sha256: "f".repeat(64), signing: { status: "unsigned" } });
    const d = eng.evaluate(ev({ kind: "process_exec", process: bad })).find((x) => x.ruleId === "exec-from-shared-temp")!;
    expect(d.action).toBe("alert");
    const res = new Feedback(eng).recordVerdict(d, "malicious", me);
    expect(res.santaSuggestion).toMatchObject({ ruleType: "BINARY", identifier: "f".repeat(64) });
    const next = eng.evaluate(ev({ kind: "process_exec", process: bad })).find((x) => x.ruleId === "user-blocked-hash");
    expect(next?.action).toBe("block");
  });

  it("refuses anything without a real user origin", () => {
    const eng = new DetectionEngine([noisy], memoryStores());
    const fb = new Feedback(eng);
    const d = eng.evaluate(ev({ kind: "process_exec", process: tool(1) }))[0]!;
    const forged = { kind: "user", via: "agent", at: 0 } as never;
    expect(() => fb.recordVerdict(d, "benign", forged)).toThrow(/approval/);
    expect(() => fb.setStage("noisy-rule", "enforce", forged)).toThrow(/approval/);
    fb.setStage("noisy-rule", "shadow", me);
    expect(eng.stageOf(eng.getRule("noisy-rule")!)).toBe("shadow");
  });
});
