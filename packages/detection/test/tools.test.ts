import { describe, expect, it } from "vitest";
import { DetectionEngine } from "../src/engine.js";
import * as api from "../src/index.js";
import { macosCoreRules } from "../src/packs/macos-core.js";
import { RulePipeline } from "../src/proposals/pipeline.js";
import { detectionToolJsonSchemas, handleDetectionTool } from "../src/proposals/tools.js";
import { memoryStores } from "../src/state/stores.js";
import { chrome, ev, proc, T0 } from "./fixtures.js";

describe("AI tool surface", () => {
  it("exposes JSON Schemas for exactly four tools", () => {
    const s = detectionToolJsonSchemas();
    expect(Object.keys(s).sort()).toEqual(["get_rule_language", "get_telemetry_summary", "propose_rule", "propose_tuning"]);
    expect(JSON.stringify(s.propose_rule.inputSchema)).toContain("rationale");
  });

  it("does not export a way to mint user approval from the package root", () => {
    expect(Object.keys(api)).not.toContain("userOrigin");
    expect(Object.keys(api)).not.toContain("mintUserOrigin");
  });

  it("summaries are aggregated and redacted", () => {
    const stores = memoryStores();
    const engine = new DetectionEngine(macosCoreRules, stores);
    const pipeline = new RulePipeline(engine, stores.history, undefined, { now: () => T0 + 1e7 });
    const secret = proc({ path: "/Users/alex.smith/code/tool", args: ["tool", "--token=sk-live-123", "alex@example.com"], signing: { status: "adhoc" } });
    engine.evaluate(ev({ kind: "process_exec", process: secret }));
    engine.evaluate(ev({ kind: "network_connect", process: secret, network: { remoteAddress: "140.82.112.3", domain: "github.com" } }));
    engine.evaluate(ev({ kind: "network_connect", process: chrome, network: { remoteAddress: "142.250.1.1", domain: "google.com" } }));
    const out = handleDetectionTool("get_telemetry_summary", { sinceHours: 24 }, { engine, pipeline, history: stores.history, provider: "claude", now: () => T0 + 1e7 });
    const text = JSON.stringify(out);
    expect(text).not.toContain("alex.smith");
    expect(text).not.toContain("sk-live-123");
    expect(text).not.toContain("alex@example.com");
    expect(text).toContain("~/code/tool");
  });

  it("guide lists fields and constraints", () => {
    const stores = memoryStores();
    const engine = new DetectionEngine([], stores);
    const pipeline = new RulePipeline(engine, stores.history);
    const out = handleDetectionTool("get_rule_language", {}, { engine, pipeline, history: stores.history, provider: "claude" }) as { guide: { fields: string[]; constraints: string[] } };
    expect(out.guide.fields).toContain("process.signing.teamId");
    expect(out.guide.constraints.length).toBeGreaterThan(3);
    expect(handleDetectionTool("delete_everything", {}, { engine, pipeline, history: stores.history, provider: "claude" }).ok).toBe(false);
  });
});
