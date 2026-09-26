import { describe, expect, it } from "vitest";
import { compileCondition, globToRegExp, regexProblem, renderTemplate } from "../src/rules/compile.js";
import type { EvalState } from "../src/rules/compile.js";
import { ev, proc } from "./fixtures.js";

const none: EvalState = { baselineHas: () => false, listHas: () => false };

describe("globToRegExp", () => {
  it("expands ~ to any user's home and handles ** and *", () => {
    const r = globToRegExp("~/Library/Application Support/Google/Chrome/**/Cookies");
    expect(r.test("/Users/alex/Library/Application Support/Google/Chrome/Default/Cookies")).toBe(true);
    expect(r.test("/Users/alex/Library/Application Support/Google/Chrome/Profile 2/Network/Cookies")).toBe(true);
    expect(r.test("/Users/alex/Library/Application Support/Google/Chrome/Cookies")).toBe(true);
    expect(r.test("/Users/alex/Library/Application Support/Google/Chrome/Default/Cookies-journal")).toBe(false);
    expect(globToRegExp("/usr/bin/*").test("/usr/bin/sub/x")).toBe(false);
  });
  it("is case-insensitive by default, like APFS", () => {
    expect(globToRegExp("~/.ssh/id_*").test("/Users/alex/.SSH/ID_ed25519")).toBe(true);
    expect(globToRegExp("~/.ssh/id_*", false).test("/Users/alex/.SSH/ID_ed25519")).toBe(false);
  });
  it("escapes regex characters", () => {
    expect(globToRegExp("/a/(b)+.c").test("/a/(b)+.c")).toBe(true);
    expect(globToRegExp("/a/(b)+.c").test("/a/bb.c")).toBe(false);
  });
});

describe("regexProblem", () => {
  it("rejects catastrophic patterns and backreferences", () => {
    expect(regexProblem("(a+)+$")).toMatch(/nested/);
    expect(regexProblem("(.*)*x")).toMatch(/nested/);
    expect(regexProblem("(a|b+){2,}")).toMatch(/nested/);
    expect(regexProblem("(a)\\1")).toMatch(/backreference/);
    expect(regexProblem("x".repeat(300))).toMatch(/longer/);
    expect(regexProblem("([")).toMatch(/compile/);
  });
  it("accepts ordinary patterns", () => {
    expect(regexProblem("(curl|wget)\\s[^|]*\\|\\s*(ba|z)?sh\\b")).toBeUndefined();
    expect(regexProblem("\\|\\s*(sudo\\s+)?sh")).toBeUndefined();
  });
});

describe("operators", () => {
  const e = ev({
    kind: "network_connect",
    process: proc({ path: "/opt/x/agent", args: ["agent", "--Mode", "fast"] }),
    network: { remoteAddress: "10.1.2.3", remotePort: 443, domain: "a.example.test" },
  });
  const t = (c: Parameters<typeof compileCondition>[0]) => compileCondition(c).test(e, none);

  it("matches array fields element-wise", () => {
    expect(t({ field: "process.args", op: "eq", value: "--Mode" })).toBe(true);
    expect(t({ field: "process.args", op: "eq", value: "--mode" })).toBe(false);
    expect(t({ field: "process.args", op: "eq", value: "--mode", ignoreCase: true })).toBe(true);
  });
  it("handles computed fields", () => {
    expect(t({ field: "process.name", op: "eq", value: "agent" })).toBe(true);
    expect(t({ field: "process.commandLine", op: "contains", value: "--Mode fast" })).toBe(true);
  });
  it("handles cidr, numbers and exists", () => {
    expect(t({ field: "network.remoteAddress", op: "cidr", value: ["10.0.0.0/8"] })).toBe(true);
    expect(t({ field: "network.remoteAddress", op: "cidr", value: ["192.168.0.0/16"] })).toBe(false);
    expect(t({ field: "network.remotePort", op: "gt", value: 400 })).toBe(true);
    expect(t({ field: "process.quarantine", op: "exists" })).toBe(false);
    expect(t({ field: "process.quarantine", op: "exists", value: false })).toBe(true);
  });
  it("neq and notIn do not match a missing field", () => {
    expect(t({ field: "process.signing.status", op: "neq", value: "apple" })).toBe(false);
    expect(t({ field: "process.signing.status", op: "notIn", value: ["apple"] })).toBe(false);
  });
  it("combines all, any and not", () => {
    expect(
      t({
        all: [
          { field: "network.remotePort", op: "eq", value: 443 },
          { not: { field: "network.domain", op: "endsWith", value: ".apple.com" } },
          { any: [{ field: "process.name", op: "eq", value: "nope" }, { field: "process.name", op: "startsWith", value: "ag" }] },
        ],
      }),
    ).toBe(true);
  });
});

describe("renderTemplate", () => {
  it("fills fields and marks missing ones", () => {
    const e = ev({ kind: "process_exec", process: proc({ path: "/tmp/x" }) });
    expect(renderTemplate("{{process.name}} from {{process.path}} via {{network.domain}}", e)).toBe(
      "x from /tmp/x via unknown",
    );
  });
});
