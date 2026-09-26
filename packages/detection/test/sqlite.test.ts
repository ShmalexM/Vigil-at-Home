import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import { DetectionEngine } from "../src/engine.js";
import { Feedback } from "../src/feedback.js";
import { mergeRules } from "../src/merge.js";
import { macosCoreRules } from "../src/packs/macos-core.js";
import { RulePipeline } from "../src/proposals/pipeline.js";
import { sqliteStores, type SqlDatabase } from "../src/state/sqlite.js";
import { userOrigin } from "../src/user.js";
import { DAY, ev, proc, T0 } from "./fixtures.js";

describe("SQLite stores", () => {
  it("persist baseline, lists, exceptions, stages, history, proposals and approved rules across restarts", () => {
    const db = new DatabaseSync(":memory:") as unknown as SqlDatabase;
    const me = userOrigin("test");
    const now = () => T0 + DAY;

    // First run.
    {
      const stores = sqliteStores(db);
      stores.lists.replace("known_bad_domains", ["evil.test"], { source: "feed", updatedAt: T0 });
      const engine = new DetectionEngine(mergeRules(macosCoreRules, stores.rules.list()), stores);
      const pipeline = new RulePipeline(engine, stores.history, stores.proposals, { now, repository: stores.rules });
      const item = ev({ kind: "persistence_added", persistence: { type: "launch_agent", itemPath: "/Users/a/Library/LaunchAgents/x.plist", programPath: "/Applications/X.app/x" } });
      const d = engine.evaluate(item).find((x) => x.ruleId === "persistence-first-seen")!;
      new Feedback(engine, undefined, now).recordVerdict(d, "benign", me, { event: item });
      new Feedback(engine).setStage("unsigned-first-network", "alert", me);
      const res = pipeline.submitRule(
        {
          rule: { id: "paste", title: "Paste site", kinds: ["network_connect"], severity: "low", action: "alert", condition: { field: "network.domain", op: "eq", value: "paste.ee" }, reasons: ["paste"] },
          rationale: "Paste sites move stolen data.",
        },
        "claude",
      );
      pipeline.approve(res.proposalId!, me);
    }

    // Second run on the same database.
    const stores = sqliteStores(db);
    const engine = new DetectionEngine(mergeRules(macosCoreRules, stores.rules.list()), stores);
    expect(stores.baseline.size()).toBe(1);
    expect(stores.lists.has("known_bad_domains", "a.evil.test")).toBe(true);
    expect(stores.exceptions.all()).toHaveLength(1);
    expect(engine.stageOf(engine.getRule("unsigned-first-network")!)).toBe("alert");
    expect(engine.getRule("ai-paste")).toMatchObject({ origin: "ai", stage: "alert" });
    expect([...stores.history.range(0, T0 + 10 * DAY)]).toHaveLength(1);
    expect(stores.proposals.list()[0]!.status).toBe("approved");
    expect(stores.ruleState.verdicts("persistence-first-seen", 0)).toHaveLength(1);
    expect(stores.history.prune(T0 + 10 * DAY)).toBe(1);

    const again = ev({ kind: "network_connect", process: proc({ path: "/opt/x" }), network: { domain: "paste.ee" } });
    expect(engine.evaluate(again).map((d) => d.ruleId)).toContain("ai-paste");
  });

  it("migrations are idempotent", () => {
    const db = new DatabaseSync(":memory:") as unknown as SqlDatabase;
    sqliteStores(db);
    expect(() => sqliteStores(db)).not.toThrow();
  });
});
