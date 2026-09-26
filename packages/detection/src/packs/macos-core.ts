import type { RuleInput } from "../rules/schema.js";

/**
 * Built-in macOS rules.
 *
 * Only rules with a very low false-positive rate start at "enforce" (known-bad
 * lists, the user's own confirmed blocks, untrusted programs reading browser
 * credentials, fake password dialogs, TCC tampering). Behaviour rules start at
 * "alert": they warn but never pause or block until the user promotes them.
 * Noisy-but-useful signals start at "shadow" and only feed the weekly review
 * and the AI's rule proposals.
 */

const UNTRUSTED_SIGNING = ["unsigned", "adhoc", "invalid"];
const SHELLS = ["sh", "bash", "zsh", "dash", "ksh"];
const SCRIPT_RUNNERS = ["osascript", "python", "python3", "perl", "ruby", "sqlite3", "curl", ...SHELLS];

export const CREDENTIAL_STORE_GLOBS = [
  "~/Library/Application Support/Google/Chrome/**/Cookies",
  "~/Library/Application Support/Google/Chrome/**/Login Data",
  "~/Library/Application Support/Google/Chrome/**/Web Data",
  "~/Library/Application Support/Google/Chrome/**/Local Extension Settings/**",
  "~/Library/Application Support/BraveSoftware/Brave-Browser/**/Cookies",
  "~/Library/Application Support/BraveSoftware/Brave-Browser/**/Login Data",
  "~/Library/Application Support/BraveSoftware/Brave-Browser/**/Local Extension Settings/**",
  "~/Library/Application Support/Microsoft Edge/**/Cookies",
  "~/Library/Application Support/Microsoft Edge/**/Login Data",
  "~/Library/Application Support/Arc/User Data/**/Cookies",
  "~/Library/Application Support/Arc/User Data/**/Login Data",
  "~/Library/Application Support/Firefox/Profiles/**/cookies.sqlite",
  "~/Library/Application Support/Firefox/Profiles/**/logins.json",
  "~/Library/Application Support/Firefox/Profiles/**/key4.db",
  "~/Library/Cookies/Cookies.binarycookies",
  "~/Library/Containers/com.apple.Safari/Data/Library/Cookies/**",
  "~/Library/Keychains/**",
  "~/.ssh/id_*",
  "~/Library/Application Support/Exodus/**",
  "~/Library/Application Support/Electrum/wallets/**",
  "~/Library/Application Support/atomic/**",
];

const USER_WRITABLE_EXEC_GLOBS = ["/tmp/**", "/private/tmp/**", "/Users/Shared/**", "/private/var/tmp/**"];

export const macosCoreRules: RuleInput[] = [
  // ---------------------------------------------------------------- enforce
  {
    id: "known-bad-hash",
    title: "Known malware started",
    description: "The program's SHA-256 is on a known-malware list.",
    kinds: ["process_exec"],
    severity: "critical",
    action: "block",
    stage: "enforce",
    condition: { inList: { list: "known_bad_sha256", field: "process.sha256" } },
    reasons: ["{{process.name}} matches a known-malware fingerprint.", "It was started from {{process.path}}."],
    santa: { ruleType: "BINARY", from: "process.sha256" },
    tags: ["attack.execution"],
  },
  {
    id: "user-blocked-hash",
    title: "Program you blocked started again",
    description: "You confirmed this exact program as malicious before.",
    kinds: ["process_exec"],
    severity: "critical",
    action: "block",
    stage: "enforce",
    condition: { inList: { list: "user_blocked_sha256", field: "process.sha256" } },
    reasons: ["You blocked {{process.name}} before, and it tried to run again."],
    santa: { ruleType: "BINARY", from: "process.sha256" },
  },
  {
    id: "known-bad-destination",
    title: "Connection to a known-malicious address",
    description: "A program connected to an IP or domain on a threat list.",
    kinds: ["network_connect"],
    severity: "high",
    action: "block",
    stage: "enforce",
    target: "network",
    condition: {
      any: [
        { inList: { list: "known_bad_ips", field: "network.remoteAddress" } },
        { inList: { list: "known_bad_domains", field: "network.domain" } },
      ],
    },
    reasons: [
      "{{process.name}} connected to {{network.domain}} ({{network.remoteAddress}}), which is on a threat list.",
      "Vigil blocks the address. The program itself keeps running.",
    ],
    dedupe: { key: ["network.remoteAddress"], windowSec: 3600 },
    tags: ["attack.command_and_control"],
  },
  {
    id: "credential-theft-untrusted",
    title: "Untrusted program reading passwords or cookies",
    description:
      "An unsigned program or a script tool opened browser cookies, saved passwords, the keychain, SSH keys or a crypto wallet. This is how infostealers like Atomic Stealer work.",
    kinds: ["file_open"],
    severity: "critical",
    action: "suspend",
    stage: "enforce",
    condition: {
      all: [
        { field: "file.path", op: "glob", value: CREDENTIAL_STORE_GLOBS },
        {
          any: [
            { field: "process.signing.status", op: "in", value: UNTRUSTED_SIGNING },
            { field: "process.name", op: "in", value: SCRIPT_RUNNERS, ignoreCase: true },
          ],
        },
      ],
    },
    reasons: [
      "{{process.name}} opened {{file.name}}, which holds saved passwords, cookies or keys.",
      "{{process.name}} is not a signed app you installed (signing: {{process.signing.status}}).",
    ],
    santa: { ruleType: "BINARY", from: "process.sha256" },
    tags: ["attack.credential_access", "attack.t1555"],
  },
  {
    id: "fake-password-prompt",
    title: "Script showing a fake password dialog",
    description: "osascript asked for a hidden answer, the trick infostealers use to get your login password.",
    kinds: ["process_exec"],
    severity: "critical",
    action: "suspend",
    stage: "enforce",
    condition: {
      all: [
        { field: "process.name", op: "eq", value: "osascript" },
        { field: "process.commandLine", op: "contains", value: "display dialog", ignoreCase: true },
        { field: "process.commandLine", op: "contains", value: "hidden answer", ignoreCase: true },
      ],
    },
    reasons: [
      "A script opened a password box that did not come from macOS.",
      "It was started by {{process.parentName}}. Do not type your password into it.",
    ],
    tags: ["attack.credential_access", "attack.t1056.002"],
  },
  {
    id: "tcc-database-tamper",
    title: "Privacy settings database modified",
    description: "A program other than macOS wrote to the TCC database that records camera, microphone and disk permissions.",
    kinds: ["file_write", "file_rename"],
    severity: "critical",
    action: "suspend",
    stage: "enforce",
    condition: {
      all: [
        {
          any: [
            { field: "file.path", op: "glob", value: ["**/com.apple.TCC/TCC.db*"] },
            { field: "file.targetPath", op: "glob", value: ["**/com.apple.TCC/TCC.db*"] },
          ],
        },
        { field: "process.signing.status", op: "neq", value: "apple" },
      ],
    },
    reasons: ["{{process.name}} changed the database that controls which apps may use your camera, microphone and files."],
    santa: { ruleType: "BINARY", from: "process.sha256" },
    tags: ["attack.defense_evasion", "attack.t1548"],
  },
  {
    id: "santa-blocked-launch",
    title: "Blocked before it could run",
    description: "Santa stopped a program from launching.",
    kinds: ["santa_block"],
    severity: "high",
    action: "alert",
    stage: "enforce",
    condition: { field: "kind", op: "eq", value: "santa_block" },
    reasons: ["{{process.name}} was stopped before it started ({{santa.reason}})."],
  },

  // ------------------------------------------------------------------ alert
  {
    id: "download-pipe-to-shell",
    title: "Downloaded script run directly",
    description:
      "A shell ran something straight from curl or wget. Some installers do this, but so do fake 'paste this into Terminal' fixes.",
    kinds: ["process_exec"],
    severity: "medium",
    action: "suspend",
    stage: "alert",
    condition: {
      all: [
        { field: "process.name", op: "in", value: SHELLS },
        {
          any: [
            { field: "process.commandLine", op: "regex", value: ["(curl|wget)\\s[^|]*\\|\\s*(sudo\\s+)?(ba|z|da)?sh\\b"] },
            { field: "process.commandLine", op: "contains", value: ["$(curl", "$(wget"] },
          ],
        },
      ],
    },
    reasons: [
      "A command downloaded code from the internet and ran it right away.",
      "If you just pasted this from a site you trust (for example an installer), you can allow it.",
    ],
    tags: ["attack.execution", "attack.t1059.004"],
  },
  {
    id: "base64-pipe-to-shell",
    title: "Hidden script decoded and run",
    description: "A command decoded base64 text and piped it into a shell, a common way to hide what it does.",
    kinds: ["process_exec"],
    severity: "high",
    action: "suspend",
    stage: "alert",
    condition: {
      field: "process.commandLine",
      op: "regex",
      value: ["base64\\s+(-d|-D|--decode)[^|]*\\|\\s*(sudo\\s+)?(ba|z|da)?sh\\b"],
    },
    reasons: ["A command unpacked hidden text and ran it as a script."],
    tags: ["attack.defense_evasion", "attack.t1140"],
  },
  {
    id: "unsigned-quarantined-exec",
    title: "Unsigned download opened",
    description: "A program downloaded from the internet, with no valid signature, started running.",
    kinds: ["process_exec"],
    severity: "high",
    action: "suspend",
    stage: "alert",
    condition: {
      all: [
        { field: "process.quarantine", op: "exists" },
        { field: "process.signing.status", op: "in", value: UNTRUSTED_SIGNING },
      ],
    },
    reasons: [
      "{{process.name}} came from the internet ({{process.quarantine.originUrl}}) and is not signed by an identified developer.",
    ],
    santa: { ruleType: "BINARY", from: "process.sha256" },
    tags: ["attack.execution", "attack.t1204.002"],
  },
  {
    id: "quarantine-removed",
    title: "Download safety check removed",
    description: "xattr removed the quarantine flag that makes macOS check downloaded apps.",
    kinds: ["process_exec"],
    severity: "medium",
    action: "alert",
    stage: "alert",
    condition: {
      all: [
        { field: "process.name", op: "eq", value: "xattr" },
        {
          any: [
            { field: "process.args", op: "eq", value: "com.apple.quarantine" },
            { field: "process.args", op: "in", value: ["-c", "-cr", "-rc"] },
          ],
        },
      ],
    },
    reasons: ["Something removed macOS's downloaded-file check: {{process.commandLine}}"],
    tags: ["attack.defense_evasion", "attack.t1553.001"],
  },
  {
    id: "gatekeeper-disabled",
    title: "Gatekeeper turned off",
    description: "spctl was used to turn off Gatekeeper, which checks apps before they open.",
    kinds: ["process_exec"],
    severity: "high",
    action: "alert",
    stage: "alert",
    condition: {
      all: [
        { field: "process.name", op: "eq", value: "spctl" },
        { field: "process.args", op: "in", value: ["--master-disable", "--global-disable"] },
      ],
    },
    reasons: ["Gatekeeper, which checks apps before they open, was switched off by {{process.parentName}}."],
    tags: ["attack.defense_evasion", "attack.t1553.001"],
  },
  {
    id: "keychain-dump",
    title: "Keychain dumped",
    description: "The security tool was asked to dump the keychain.",
    kinds: ["process_exec"],
    severity: "high",
    action: "suspend",
    stage: "alert",
    condition: {
      all: [
        { field: "process.name", op: "eq", value: "security" },
        { field: "process.args", op: "eq", value: "dump-keychain" },
      ],
    },
    reasons: ["{{process.parentName}} asked macOS to dump your keychain."],
    tags: ["attack.credential_access", "attack.t1555.001"],
  },
  {
    id: "exec-from-shared-temp",
    title: "New program started from a temporary folder",
    description: "An unsigned program ran from /tmp or /Users/Shared for the first time.",
    kinds: ["process_exec"],
    severity: "medium",
    action: "suspend",
    stage: "alert",
    condition: {
      all: [
        { field: "process.path", op: "glob", value: USER_WRITABLE_EXEC_GLOBS },
        { field: "process.signing.status", op: "in", value: UNTRUSTED_SIGNING },
        { firstSeen: { key: ["process.path"] } },
      ],
    },
    reasons: ["{{process.name}} ran from {{process.path}}, a shared or temporary folder, and is not signed."],
    santa: { ruleType: "BINARY", from: "process.sha256" },
    tags: ["attack.execution"],
  },
  {
    id: "persistence-suspicious-program",
    title: "Something set itself to run at login",
    description:
      "A launch item was added that runs a script, a downloader, or a program in a temporary folder.",
    kinds: ["persistence_added"],
    severity: "high",
    action: "block",
    stage: "alert",
    target: "persistence",
    condition: {
      any: [
        { field: "persistence.programPath", op: "glob", value: USER_WRITABLE_EXEC_GLOBS },
        {
          field: "persistence.commandLine",
          op: "regex",
          value: ["\\b(curl|wget|osascript|base64)\\b", "\\bpython[0-9.]*\\s+-c\\b", "\\b(ba|z)?sh\\s+-c\\b"],
        },
      ],
    },
    reasons: ["{{persistence.itemPath}} will run {{persistence.commandLine}} every time you log in."],
    tags: ["attack.persistence", "attack.t1543.001"],
  },
  {
    id: "persistence-apple-lookalike",
    title: "Login item pretending to be Apple",
    description: "A launch item outside /System uses a com.apple. label.",
    kinds: ["persistence_added"],
    severity: "high",
    action: "block",
    stage: "alert",
    target: "persistence",
    condition: {
      all: [
        { field: "persistence.label", op: "startsWith", value: "com.apple.", ignoreCase: true },
        {
          field: "persistence.itemPath",
          op: "glob",
          value: ["~/Library/LaunchAgents/**", "/Library/LaunchAgents/**", "/Library/LaunchDaemons/**"],
        },
      ],
    },
    reasons: ["{{persistence.label}} is named like an Apple item but was added to {{persistence.itemPath}}."],
    tags: ["attack.persistence", "attack.t1036"],
  },
  {
    id: "persistence-first-seen",
    title: "New login item",
    description: "Something new set itself to start automatically.",
    kinds: ["persistence_added"],
    severity: "low",
    action: "alert",
    stage: "alert",
    target: "persistence",
    condition: { firstSeen: { key: ["persistence.itemPath"] } },
    reasons: ["{{persistence.itemPath}} was added and will start {{persistence.programName}} automatically."],
    tags: ["attack.persistence"],
  },
  {
    id: "new-network-listener",
    title: "New app accepting connections from the network",
    description: "A program that is not part of macOS started listening on all network interfaces.",
    kinds: ["listening_port"],
    severity: "low",
    action: "alert",
    stage: "alert",
    condition: {
      all: [
        { field: "network.localAddress", op: "in", value: ["0.0.0.0", "::", "*"] },
        { field: "process.signing.status", op: "neq", value: "apple" },
        { firstSeen: { key: ["process.path", "network.localPort"] } },
      ],
    },
    reasons: ["{{process.name}} is accepting connections from other devices on port {{network.localPort}}."],
    tags: ["attack.command_and_control"],
  },
  {
    id: "browser-extension-broad-access",
    title: "New browser extension that can read every site",
    description: "An extension was installed with access to all sites, cookies or native apps.",
    kinds: ["browser_extension_added"],
    severity: "medium",
    action: "alert",
    stage: "alert",
    condition: {
      all: [
        {
          field: "extension.permissions",
          op: "in",
          value: ["<all_urls>", "cookies", "debugger", "nativeMessaging", "*://*/*", "http://*/*", "https://*/*"],
        },
        { firstSeen: { key: ["extension.browser", "extension.id"] } },
      ],
    },
    reasons: ["{{extension.name}} was added to {{extension.browser}} and can read or change what you do on websites."],
    tags: ["attack.persistence", "attack.t1176"],
  },
  {
    id: "mass-document-reads",
    title: "Unsigned program reading many documents",
    description: "An unsigned program opened a large number of files in Documents or Desktop within a minute.",
    kinds: ["file_open"],
    severity: "high",
    action: "suspend",
    stage: "alert",
    condition: {
      all: [
        { field: "file.path", op: "glob", value: ["~/Documents/**", "~/Desktop/**"] },
        { field: "process.signing.status", op: "in", value: UNTRUSTED_SIGNING },
      ],
    },
    threshold: { count: 50, withinSec: 60, groupBy: ["process.pid"] },
    reasons: ["{{process.name}} opened 50 or more of your documents in under a minute."],
    tags: ["attack.collection", "attack.t1005"],
  },

  // ----------------------------------------------------------------- shadow
  {
    id: "unsigned-first-network",
    title: "Unsigned program's first network connection",
    description:
      "An unsigned or ad-hoc signed program connected out for the first time. Common for developer tools, so it only records and feeds the weekly review.",
    kinds: ["network_connect"],
    severity: "low",
    action: "alert",
    stage: "shadow",
    condition: {
      all: [
        { field: "process.signing.status", op: "in", value: UNTRUSTED_SIGNING },
        { firstSeen: { key: ["process.path"] } },
      ],
    },
    reasons: ["{{process.name}} ({{process.path}}) connected to {{network.remoteAddress}} for the first time."],
    tags: ["attack.command_and_control"],
  },
];
