import { describe, expect, it } from "vitest";
import { DetectionEngine } from "../src/engine.js";
import { macosCoreRules } from "../src/packs/macos-core.js";
import { memoryStores } from "../src/state/stores.js";
import type { SensorEvent } from "../src/types.js";
import { chrome, proc, T0 } from "./fixtures.js";

describe("inline cost", () => {
  it("evaluates the full pack well under a millisecond per event", () => {
    const stores = memoryStores();
    stores.lists.replace("known_bad_sha256", Array.from({ length: 100_000 }, (_, i) => i.toString(16).padStart(64, "0")), { source: "t", updatedAt: 0 });
    const engine = new DetectionEngine(macosCoreRules, stores, { recordHistory: false });
    const kinds = ["process_exec", "file_open", "network_connect", "file_write"] as const;
    const events: SensorEvent[] = [];
    for (let i = 0; i < 100_000; i++) {
      const p = i % 3 === 0 ? chrome : proc({ path: `/Users/a/code/bin/t${i % 500}`, args: ["t", "--x", String(i)], signing: { status: "adhoc" }, sha256: (i % 700).toString(16).padStart(64, "f") });
      events.push({
        id: `p${i}`,
        ts: T0 + i * 10,
        source: "osquery",
        kind: kinds[i % 4]!,
        process: p,
        file: { path: `/Users/a/Library/Application Support/App/file${i % 50}.db` },
        network: { remoteAddress: `140.82.${i % 250}.${i % 200}`, domain: `h${i % 900}.example.test` },
      });
    }
    const start = performance.now();
    for (const e of events) engine.evaluate(e);
    const perEventUs = ((performance.now() - start) * 1000) / events.length;
    console.log(`full pack: ${perEventUs.toFixed(1)} µs per event`);
    expect(perEventUs).toBeLessThan(200);
  });
});
