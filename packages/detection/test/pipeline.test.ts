import { describe, expect, it } from "vitest";
import { DetectionEngine } from "../src/engine.js";
import { macosCoreRules } from "../src/packs/macos-core.js";
import { RulePipeline } from "../src/proposals/pipeline.js";
import { handleDetectionTool } from "../src/proposals/tools.js";
import { memoryStores } from "../src/state/stores.js";
import type { SensorEvent } from "../src/types.js";
import { userOrigin } from "../src/user.js";
import { chrome, DAY, HOUR, proc, T0 } from "./fixtures.js";

const NOW = T0 + 14 * DAY;
const devTool = proc({ path: "/Users/alex/code/app/bin/server", signing: { status: "adhoc" }, sha256: "1".repeat(64) });
const node = proc({ path: "/opt/homebrew/bin/node", signing: { status: "adhoc" }, sha256: "2".repeat(64) });
const stealer = proc({ path: "/Users/alex/Library/.cache/upd", signing: { status: "adhoc" }, sha256: "9".repeat(64) });

/** Two weeks of ordinary activity with a little exfiltration near the end. */
function setup(opts: { maxPerDay?: number } = {}) {
  const stores = memoryStores();
  let n = 0;
  const add = (e: Omit<SensorEvent, "id" | "source">) => stores.history.append({ id: `h${n++}`, source: "osquery", ...e });
  for (let t = T0; t < NOW; t += HOUR) {
    add({ ts: t, kind: "network_connect", process: chrome, network: { remoteAddress: "142.250.1.1", domain: "google.com" } });
    add({ ts: t + 60_000, kind: "network_connect", process: devTool, network: { remoteAddress: "140.82.112.3", domain: "github.com" } });
  }
  add({ ts: NOW - 2 * DAY, kind: "network_connect", process: node, network: { remoteAddress: "104.20.1.1", domain: "pastebin.com" } });
  add({ ts: NOW - 1 * DAY, kind: "network_connect", process: stealer, network: { remoteAddress: "104.20.1.2", domain: "paste.ee" } });
  const engine = new DetectionEngine(macosCoreRules, stores, { recordHistory: false });
  const pipeline = new RulePipeline(engine, stores.history, undefined, { now: () => NOW, maxPerDay: opts.maxPerDay });
  return { stores, engine, pipeline };
}

const pasteRule = {
  id: "paste-site-upload",
  title: "Program talking to a paste site",
  kinds: ["network_connect"],
  severity: "medium",
  action: "alert",
  stage: "enforce",
  condition: {
    all: [
      { field: "network.domain", op: "in", value: ["pastebin.com", "paste.ee"] },
      { field: "process.signing.status", op: "in", value: ["unsigned", "adhoc"] },
    ],
  },
  reasons: ["{{process.name}} sent data to {{network.domain}}, a paste site used to move stolen data."],
};

describe("AI rule proposals", () => {
  it("replays a proposal, ignores the AI's stage, and waits for the user", () => {
    const { pipeline, engine } = setup();
    const res = pipeline.submitRule({ rule: pasteRule, rationale: "Unsigned programs uploading to paste sites is how stealers exfiltrate." }, "claude");
    expect(res.errors).toEqual([]);
    expect(res.ok).toBe(true);
    expect(res.status).toBe("awaiting_review");
    expect(res.replay).toMatchObject({ hits: 2, popups: 2, verdict: "quiet", hitsOnAppleSigned: 0 });
    const p = pipeline.get(res.proposalId!)!;
    expect(p.rule.id).toBe("ai-paste-site-upload");
    expect(p.rule.stage).toBe("shadow");
    expect(p.rule.origin).toBe("ai");
    // Not live until the user approves.
    expect(engine.getRule("ai-paste-site-upload")).toBeUndefined();
  });

  it("goes live at the stage the user picks, default alert", () => {
    const { pipeline, engine } = setup();
    const { proposalId } = pipeline.submitRule({ rule: pasteRule, rationale: "Paste sites are exfil channels." }, "claude");
    expect(() => pipeline.approve(proposalId!, { kind: "user", via: "agent", at: 0 } as never)).toThrow(/approval/);
    const live = pipeline.approve(proposalId!, userOrigin("rules-screen"));
    expect(live.stage).toBe("alert");
    expect(engine.stageOf(live)).toBe("alert");
    const d = engine.evaluate({ id: "new", ts: NOW + 1, kind: "network_connect", source: "osquery", process: node, network: { domain: "paste.ee", remoteAddress: "104.20.1.3" } });
    expect(d.find((x) => x.ruleId === "ai-paste-site-upload")?.action).toBe("alert");
    expect(pipeline.get(proposalId!)).toMatchObject({ status: "approved", decidedVia: "rules-screen", approvedStage: "alert" });
  });

  it("flags a rule that would interrupt the user all day as noisy", () => {
    const { pipeline } = setup();
    const res = pipeline.submitRule(
      {
        rule: { ...pasteRule, id: "google", condition: { field: "network.domain", op: "eq", value: "google.com" } },
        rationale: "Testing a very broad rule here.",
      },
      "codex",
    );
    expect(res.ok).toBe(true);
    expect(res.replay!.verdict).toBe("noisy");
    expect(res.replay!.notes.join(" ")).toMatch(/times a day/);
  });

  it("refuses to let the AI block on behaviour alone", () => {
    const { pipeline } = setup();
    const res = pipeline.submitRule({ rule: { ...pasteRule, action: "block", target: "network", condition: { field: "process.signing.status", op: "eq", value: "adhoc" } }, rationale: "Block every ad-hoc program." }, "claude");
    expect(res.ok).toBe(false);
    expect(res.status).toBe("rejected_by_checks");
    expect(res.errors.join(" ")).toMatch(/can only block when it names a specific/);
  });

  it("allows an AI block rule anchored on a specific hash", () => {
    const { pipeline } = setup();
    const res = pipeline.submitRule(
      { rule: { ...pasteRule, id: "stealer-hash", action: "block", severity: "critical", condition: { field: "process.sha256", op: "eq", value: "9".repeat(64) } }, rationale: "This exact binary exfiltrated data." },
      "claude",
    );
    expect(res.errors).toEqual([]);
    expect(res.replay!.hits).toBe(1);
  });

  it("returns fixable errors for malformed rules and unknown lists", () => {
    const { pipeline } = setup();
    const bad1 = pipeline.submitRule({ rule: { id: "x-rule", title: "x" }, rationale: "missing everything here" }, "claude");
    expect(bad1.ok).toBe(false);
    expect(bad1.errors.length).toBeGreaterThan(0);
    const bad2 = pipeline.submitRule(
      { rule: { ...pasteRule, id: "lists", condition: { inList: { list: "made_up_list", field: "network.domain" } } }, rationale: "Uses a list that does not exist." },
      "claude",
    );
    expect(bad2.errors.join(" ")).toMatch(/made_up_list/);
    const bad3 = pipeline.submitRule({ rule: { ...pasteRule, id: "only-exists", condition: { field: "network.domain", op: "exists" } }, rationale: "Fires on anything with a domain." }, "claude");
    expect(bad3.errors.join(" ")).toMatch(/specific/);
  });

  it("rate-limits proposals per provider per day", () => {
    const { pipeline } = setup({ maxPerDay: 2 });
    for (const id of ["a-one", "a-two"]) expect(pipeline.submitRule({ rule: { ...pasteRule, id }, rationale: "rate limit test rule" }, "claude").ok).toBe(true);
    expect(pipeline.submitRule({ rule: { ...pasteRule, id: "a-three" }, rationale: "rate limit test rule" }, "claude").errors[0]).toMatch(/Limit/);
    expect(pipeline.submitRule({ rule: { ...pasteRule, id: "a-four" }, rationale: "rate limit test rule" }, "codex").ok).toBe(true);
  });

  it("feeds the user's rejection note back through the telemetry tool", () => {
    const { pipeline, engine, stores } = setup();
    const { proposalId } = pipeline.submitRule({ rule: pasteRule, rationale: "Paste sites are exfil channels." }, "claude");
    pipeline.reject(proposalId!, userOrigin("rules-screen"), "I use pastebin from node for work");
    const out = handleDetectionTool("get_telemetry_summary", { sinceHours: 72 }, { engine, pipeline, history: stores.history, provider: "claude", now: () => NOW });
    expect(out.ok).toBe(true);
    const summary = (out as { summary: { recentProposals: Array<{ userNote?: string }> } }).summary;
    expect(summary.recentProposals[0]!.userNote).toBe("I use pastebin from node for work");
  });
});

describe("AI tuning proposals", () => {
  const baseRule = {
    id: "unsigned-net-alert",
    title: "Unsigned program online",
    kinds: ["network_connect"] as const,
    severity: "low" as const,
    action: "alert" as const,
    stage: "alert" as const,
    condition: { field: "process.signing.status", op: "in" as const, value: ["unsigned", "adhoc"] },
    reasons: ["{{process.name}} connected out"],
  };

  it("shows how many hits a narrowing removes and applies it on approval", () => {
    const { pipeline, engine } = setup();
    engine.upsertRule({ ...baseRule, kinds: [...baseRule.kinds] });
    const res = pipeline.submitTuning(
      { ruleId: "unsigned-net-alert", addExclusion: { field: "process.path", op: "glob", value: ["~/code/**"] }, rationale: "Your own builds in ~/code are expected." },
      "claude",
    );
    expect(res.errors).toEqual([]);
    const p = pipeline.get(res.proposalId!)!;
    expect(p.tuning!.removed).toBeGreaterThan(300);
    expect(p.tuning!.hitsAfter).toBe(2);
    pipeline.approve(res.proposalId!, userOrigin("rules-screen"));
    expect(engine.getRule("unsigned-net-alert")).toMatchObject({ version: 2, stage: "alert" });
  });

  it("refuses an exclusion that would hide a confirmed threat", () => {
    const { pipeline, engine, stores } = setup();
    engine.upsertRule({ ...baseRule, kinds: [...baseRule.kinds] });
    stores.lists.add("user_blocked_sha256", "9".repeat(64), { source: "user", updatedAt: 0 });
    const res = pipeline.submitTuning(
      { ruleId: "unsigned-net-alert", addExclusion: { field: "process.path", op: "glob", value: ["~/Library/**"] }, rationale: "Library helpers are fine." },
      "claude",
    );
    expect(res.ok).toBe(false);
    expect(res.errors.join(" ")).toMatch(/hide 1 detection/);
  });

  it("refuses an exclusion that matches everything", () => {
    const { pipeline, engine } = setup();
    engine.upsertRule({ ...baseRule, kinds: [...baseRule.kinds] });
    const res = pipeline.submitTuning({ ruleId: "unsigned-net-alert", addExclusion: { field: "process.path", op: "glob", value: ["/**"] }, rationale: "Silence it entirely." }, "claude");
    expect(res.errors.join(" ")).toMatch(/specific/);
  });

  it("refuses a stale approval after the rule changed", () => {
    const { pipeline, engine } = setup();
    engine.upsertRule({ ...baseRule, kinds: [...baseRule.kinds] });
    const res = pipeline.submitTuning({ ruleId: "unsigned-net-alert", addExclusion: { field: "process.path", op: "glob", value: ["~/code/**"] }, rationale: "Your own builds are expected." }, "claude");
    engine.upsertRule({ ...baseRule, kinds: [...baseRule.kinds], version: 5 });
    expect(() => pipeline.approve(res.proposalId!, userOrigin("rules-screen"))).toThrow(/changed/);
  });
});
