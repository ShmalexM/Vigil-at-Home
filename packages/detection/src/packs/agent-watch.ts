import { AGENT_CATALOG, type CatalogEntry } from '../agents/catalog.js';
import type { Condition, DetectionRuleInput } from '../types.js';
import {
  CREDENTIAL_STORE_GLOBS,
  SCRIPT_RUNNERS,
  SHELLS,
  SUSPEND,
  UNTRUSTED_SIGNING,
} from './macos-core.js';

/**
 * Agent watch: what AI agents on this Mac (Claude Code, Codex, Cursor's
 * agent...) and the programs they start actually do.
 *
 * Vigil's process tracker tags each event with the agent it runs under
 * (`process.agent`) before rules run, so these rules see only agent
 * activity: a person's own terminal is never tagged. Depth 0 is the agent
 * itself; everything it starts is one level deeper.
 *
 * No rule here blocks. Pausing is only offered on launches below the agent
 * (depth > 0) and always names that program, never the agent: stopping the
 * agent would lose the person's session, and its children are what act.
 */

/** When this pack version was written. Rules carry it as createdAt/updatedAt. */
const PACK_DATE = Date.UTC(2026, 9, 1);

type PackRule = Omit<DetectionRuleInput, 'version' | 'origin' | 'createdAt' | 'updatedAt'> & {
  version?: number;
};

function rule(r: PackRule): DetectionRuleInput {
  return { version: 1, origin: 'builtin', createdAt: PACK_DATE, updatedAt: PACK_DATE, ...r };
}

/** The event runs under a watched agent (or Vigil's own helpers). */
const AGENT = { field: 'process.agent.id', op: 'exists' } as const;
/** Started by the agent, not the agent itself. */
const CHILD = { field: 'process.agent.depth', op: 'gt', value: 0 } as const;

/**
 * The shell an agent runs, or one of these tools started directly (not via a
 * shell, so one command raises one alert, on the shell that holds all of it).
 */
const via = (names: string[]): Condition => ({
  any: [
    { field: 'process.name', op: 'in', value: SHELLS },
    {
      all: [
        { field: 'process.name', op: 'in', value: names },
        { not: { field: 'process.parentName', op: 'in', value: SHELLS } },
      ],
    },
  ],
});

/** The command line matches any of these regexes (case-sensitive). */
const cmd = (...patterns: string[]): Condition => ({
  field: 'process.commandLine',
  op: 'regex',
  value: patterns,
});
/**
 * The command line matches any of these regexes, ignoring case. macOS paths
 * are case-insensitive (APFS), so `~/.AWS/Credentials` reads the same file as
 * `~/.aws/credentials`; most checks fold case. Upload flags are the exception
 * (see UPLOAD_RES) and stay on `cmd`.
 */
const cmdI = (...patterns: string[]): Condition => ({
  field: 'process.commandLine',
  op: 'regex',
  value: patterns,
  nocase: true,
});

// ---------------------------------------------------------------- credentials
/**
 * The credential files, as a bare alternation, for reuse inside the scp/rsync
 * checks below (no leading boundary or trailing terminator).
 */
const SECRET_BODY = String.raw`(\.aws/(credentials|config|sso/cache)|\.ssh/id_(rsa|ed25519|ecdsa|dsa)|\.kube/config|\.config/gcloud/|\.netrc|\.npmrc|\.docker/config\.json|\.azure/)`;

/**
 * Credential files named in a command: an SSH private key, a kube/netrc config,
 * a cloud-provider store, or the keychain's database (copying it out is how
 * stealers take saved passwords to crack them elsewhere). Matched
 * case-insensitively (see cmdI). An SSH key
 * does not count when the command is handing it to ssh/scp/sftp as the identity
 * file (`-i`), or to `ssh-add`/`ssh-keygen`/`chmod`, or via `IdentityFile=`: the
 * tool uses its own key, it is not being read out. A kube/netrc path does not
 * count right after `--kubeconfig`/`KUBECONFIG=` or `--netrc-file`. `.npmrc`
 * counts only under a home folder, so a project-local `.npmrc` is left alone.
 */
export const SECRET_PATH_SSH = String.raw`\.ssh/(?<!((^|[\s"'=/])(ssh|scp|sftp)(\s[^|;&]{0,64})?\s-i|(^|[\s"'=/])(ssh-add|ssh-keygen|chmod)\s[^|;&]{0,64}|IdentityFile=)\s?["']?[^\s"']{0,48}\.ssh/)id_(rsa|ed25519|ecdsa|dsa)($|[\s"';|&)])`;
export const SECRET_PATH_KUBE = String.raw`(\.kube/(?<!(--kubeconfig[= ]|KUBECONFIG=)["']?[^\s"']{0,64}\.kube/)config|\.netrc(?<!--netrc-file[= ]["']?[^\s"']{0,64}\.netrc))`;
export const SECRET_PATH_CLOUD = String.raw`(\.aws/(credentials|config|sso/cache)|\.config/gcloud/|\.docker/config\.json|\.azure/|(~|\$HOME|\$\{HOME\}|/Users/[^/\s"']+)/\.npmrc|Library/Keychains\b)`;
/** The three credential-path checks, matched together (case-insensitive). */
export const SECRET_PATH_RES = [SECRET_PATH_SSH, SECRET_PATH_KUBE, SECRET_PATH_CLOUD];
/**
 * Programs that copy, pack or send a file: opening the keychain's database
 * counts for these alone (agent-secret-read).
 */
const KEYCHAIN_COPIERS = [
  'cat',
  'cp',
  'ditto',
  'rsync',
  'scp',
  'tar',
  'zip',
  'gzip',
  'base64',
  'xxd',
  'strings',
  'dd',
  'curl',
  'nc',
  'sqlite3',
];
/** Programs that print, copy or pack a file (agent-secret-command). */
const SECRET_READERS = [
  'cat',
  'less',
  'more',
  'head',
  'tail',
  'cp',
  'base64',
  'xxd',
  'strings',
  'tar',
  'zip',
  'grep',
];
/**
 * One of SECRET_READERS given a credential file in the same command, before the
 * next `|`, `;` or `&`. Paired with SECRET_PATH_RES, which drops public keys and
 * keys handed to ssh. A command that names the path for another reason
 * (`docker run -v ~/.kube/config:...`, `test -d ~/.config/gcloud/`,
 * `scp host:k3s.yaml ~/.kube/config`) is not reading it out.
 */
export const SECRET_READ_RE =
  String.raw`(^|[\s;&|('"/\x60])(${SECRET_READERS.join('|')})\s[^|;&]*` + SECRET_BODY;
/** One of SECRET_READERS (or ditto/rsync) given the keychain's database, or its folder. */
export const KEYCHAIN_READ_RE = String.raw`(^|[\s;&|('"/\x60])(${SECRET_READERS.join('|')}|ditto|rsync)\s[^|;&]*Library/Keychains\b`;

/** The same files opened directly, plus the browser and keychain stores. */
export const SECRET_FILE_GLOBS = [
  '~/.aws/credentials',
  '~/.aws/config',
  '~/.aws/sso/cache/**',
  '~/.config/gcloud/**',
  '~/.kube/config',
  '~/.netrc',
  '~/.docker/config.json',
  '~/.azure/**',
  ...CREDENTIAL_STORE_GLOBS,
];

// --------------------------------------------------------------- exfil sinks
/**
 * curl/wget/nscurl sending data out: a form, an upload or a request body.
 * Matched case-SENSITIVELY, because the flags are case-specific: `-d`/`-F`/`-T`
 * and `--data`/`--form`/`--upload-file`/`--json` send a body, while `-f`
 * (fail fast) does not. Folding case would read the `f` in `curl -fsSL` as a
 * form upload.
 */
export const UPLOAD_CURL = String.raw`\bcurl\b[^|;&\n]{0,256}\s(-[a-zA-Z]*[dFT]|--(data(-[a-z]+)?|form(-string)?|upload-file|json)\b)`;
export const UPLOAD_WGET = String.raw`\b(wget|nscurl)\b[^|;&\n]{0,256}\s--(post|body)-(file|data)\b`;
export const UPLOAD_RES = [UPLOAD_CURL, UPLOAD_WGET];
/** Output piped straight into a network tool. */
export const PIPE_SINK_RE = String.raw`\|\s*(curl|wget|nc|ncat|socat)\b`;
/**
 * A credential file copied to another host with scp/rsync (a `host:` target).
 * The leading `(?=...:)` asserts a `host:` is coming before any separator, so a
 * command with no remote target fails fast instead of backtracking. The key is
 * left alone when it is the identity file passed with `-i`, or an rsync
 * `--exclude`/`--filter` pattern or `-e "ssh -i ..."` option (`--include` is a
 * transfer, so it still counts).
 */
export const SCP_FROM =
  String.raw`\bscp\s(?=[^|;&]*:)[^|;&]*?(?<!\s-i\s{0,4}\S{0,40})` +
  SECRET_BODY +
  String.raw`[^|;&]*:`;
export const RSYNC_FROM =
  String.raw`\brsync\s(?=[^;&]*:)[^|;&]*?(?<!-e\s?["']ssh\s[^"']{0,140}|--(exclude|filter)[=\s]\s?\S{0,40})` +
  SECRET_BODY +
  String.raw`[^|;&]*:`;
export const COPY_OUT_RES = [SCP_FROM, RSYNC_FROM];
/**
 * Every environment variable piped to the network. The gap from `env |` to the
 * tool cannot cross `;`, `&` or another `|`, so two separate commands like
 * `env | grep proxy; curl host` do not count as one exfil.
 */
export const ENV_DUMP_RE = String.raw`(^|[\s;&|('"])(/usr/bin/|/bin/)?(env|printenv)\s*\|(?!\|)([^;&|\n]|\|(?!\|)){0,256}?(?<=[ \t|(/])(curl|wget|nc|ncat|socat)(?=[\s"')]|$)`;
/**
 * Paste sites, file drops and request catchers, matched only as the host part
 * of a URL: after `//`, an optional `name.`/`user@` run, then the host, then a
 * non-host-character. So `api.mix.io` is not read as `ix.io`. ngrok is left out
 * (too many ordinary tunnels). Case-insensitive.
 */
export const PASTE_HOST_RE = String.raw`//([^/\s"']*[.@])?(pastebin\.com|paste\.ee|hastebin\.\w+|0x0\.st|transfer\.sh|termbin\.com|ix\.io|dpaste\.\w+|file\.io|webhook\.site|requestbin\.\w+|pipedream\.net|bashupload\.com|temp\.sh)(?![\w.-])`;

// ---------------------------------------------------------------- persistence
/** Loading a launch item that runs the payload at login. */
export const PERSIST_LAUNCHCTL = String.raw`launchctl\s+(load|bootstrap|submit|enable)\b`;
/**
 * Installing a crontab (`crontab -e`/`-r`, or `crontab -` reading from a pipe,
 * or `crontab file`). `crontab` must be at a command position (start, after a
 * separator, or right after `eval`/`sudo`/`sh -c`), so the word in prose like
 * `echo "crontab entry"` does not count. `crontab -l` (list) is left alone.
 */
export const PERSIST_CRONTAB = String.raw`(^|[\n;&|(\x60]|(eval|sudo|sh\s+-\w*c)\s+['"]?)\s*crontab\s+(-u\s+\S+\s+)?(-[er]\b|-(\s|$|['"])|[^-\s'"])`;
/**
 * Writing into a LaunchAgents/LaunchDaemons folder, whether by copy/move/link,
 * `defaults write`, `plutil`, or a redirect. Verbs are whole words, so a home
 * folder like `/Users/mvalle` is not read as `mv`. curl/wget count too, for a
 * plist downloaded straight into the folder.
 */
export const PERSIST_WRITE = String.raw`((^|[\s;&|(/])(cp|mv|tee|ln|ditto|rsync|install|curl|wget)\b|\bdefaults\s+write\b|\bplutil\s+-(create|insert|replace|convert)\b|>\|?)(?:(?!Library/Launch|\b(cp|mv|ln|tee|ditto|rsync|install|curl|wget)\b)[^|;&>])*Library/Launch(Agents|Daemons)/`;
export const PERSIST_RES = [PERSIST_LAUNCHCTL, PERSIST_CRONTAB, PERSIST_WRITE];

// --------------------------------------------------------------------- tamper
/** A path to Vigil's or Santa's own files. */
const GUARDED_PATH = String.raw`(Vigil\\? at\\? Home(\.app\b|/)|vigil-helper|com\.vigilathome|/var/db/santa|Santa\.app)`;

/**
 * Stopping or editing Vigil or Santa, or switching off a macOS protection.
 * Matched case-insensitively; paths may escape their spaces (`Vigil\ at\ Home`).
 * The tempered gaps (`(?:(?!verb)[^|;&>])*`) stay linear: they stop at a
 * command separator and at the next verb, so one pipeline matches at most once.
 */
export const TAMPER_RES_NOCASE = [
  // kill/killall/pkill of Vigil or Santa, or a pipeline that xargs-kills it.
  String.raw`((^|[\s;&|('"/])(kill|killall|pkill)\s(?:(?![\s('"/](kill|killall|pkill)\s)[^|;&])*(vigil|santa)|(vigil|santa)[^;&]{0,200}\|\s*xargs\b[^|;&]{0,40}\bkill)`,
  // launchctl unloading/booting out Vigil or Santa.
  String.raw`launchctl\s+(bootout|unload|remove|disable|kill)\b[^|;&]*(vigil|santa)`,
  // santactl adding an allow/remove rule.
  String.raw`santactl\s+rule\b[^|;&]*--(allow|remove|whitelist)`,
  // spctl turning Gatekeeper off (or adding a blanket allowance), or csrutil
  // disabling System Integrity Protection.
  String.raw`(spctl\s+--(master-disable|global-disable|disable|add)|csrutil\s+disable)\b`,
  // tccutil resetting privacy — but a per-app reset of some other app is fine;
  // resetting All, or an app whose id names vigil/santa, is not.
  String.raw`tccutil\s+reset\b(?!\s+["']?\w+["']?\s+["']?(?![\w.-]*(vigil|santa))[\w-]+\.[\w.-]+["']?(\s|$|[;&|)]))`,
  // editing or deleting Vigil's or Santa's own files: the verb or redirect and
  // a path to them on one line, at most 160 characters apart (which also keeps
  // the gap linear). "Vigil at Home" counts only as a path (`…/Vigil at Home/`,
  // `Vigil at Home.app`), so prose in a heredoc, a note or an agent's
  // transcript that names Vigil does not. sqlite3 opening a database read-only
  // (`-readonly`, `?mode=ro`) only reads it, like any other reader.
  String.raw`(\b(rm|mv|cp|truncate|chmod|chown|tee)\b|\bsqlite3\b(?![^|;&>\n]{0,160}(\s-readonly\b|[?&]mode=ro\b))|>)[^|;&>\n]{0,160}?${GUARDED_PATH}`,
  // ...unless it writes a copy or its output there.
  String.raw`\bsqlite3\b[^|;&>\n]{0,160}?([\s"']\.(output|once|save|backup|clone|excel)|\bvacuum\s+into)\b[^|;&>\n]{0,160}?${GUARDED_PATH}`,
  // turning the firewall off, or unloading Santa's system extension.
  String.raw`(socketfilterfw\b[^|;&]{0,64}--setglobalstate\s+off\b|--unload-system-extension\b|systemextensionsctl\s+uninstall\b[^|;&]{0,128}(santa|vigil))`,
  // telling Vigil or Santa to quit over AppleScript.
  String.raw`osascript\b[^|;&]{0,160}(\bquit\s+(app|application)\b[^|;&]{0,64}(vigil|santa)|(vigil|santa)[^|;&]{0,32}\bto\s+quit\b)`,
];
/** Case-sensitive: `pfctl -d` turns the firewall off and `-F a`/`-F r`/`-F T` flush rules; `-f` loads rules and `-F states` only clears connections, both fine. */
export const TAMPER_RE_CASED = String.raw`pfctl\s+-(d\b|F\s*["']?[arT])`;

/** `field` tampers with Vigil, Santa or a macOS protection. */
export const tamper = (field: string): Condition => ({
  any: [
    { field, op: 'regex', value: TAMPER_RES_NOCASE, nocase: true },
    { field, op: 'regex', value: [TAMPER_RE_CASED] },
  ],
});

// ------------------------------------------------------------- agent settings
/** `security` printing a saved password (`-g`/`-w`) or exporting the keychain. */
export const KEYCHAIN_SECRET_RE = String.raw`security\s+(find-(generic|internet)-password\b[^|;&]*\s-[gw]|export\b|dump-keychain\b)`;
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * An agent reading back its own saved sign-in: `security
 * find-generic-password` for one of the agent's own services (catalogue
 * `keychainLogins`, each also with the 8-hex-digit suffix Claude Code adds per
 * config folder), launched by the agent's own program as is or through a bare
 * `sh -c`, wherever that program runs in the tree (Vigil's own helpers start
 * Claude Code too). The caller is the parent: its path or plain name fits the
 * catalogue, or, for a shell that reached Vigil without its parent's path, it
 * sits right under the agent itself.
 *
 * The whole command must be that one read: only -a, -s, -w and -g, one -s
 * naming its own service, nothing that chains, redirects or substitutes. On a
 * real Mac (2026-10-02, 341 shells under Claude Code) a Bash tool step always
 * arrived wrapped (`zsh -c source …snapshot… && eval '…'`, or `sh -c env
 * SANDBOX_RUNTIME=1 …`), never as a bare `sh -c <command>`, so the same read
 * asked for by text the agent read still alerts. A hook or status-line command
 * the user set to exactly this read would fit too.
 */
export function ownKeychainLogin(
  agent: Pick<CatalogEntry, 'match' | 'keychainLogins'> & { id?: string },
): Condition | undefined {
  const agentId = agent.id;
  const services = agent.keychainLogins ?? [];
  const paths = agent.match.flatMap((m) => m.paths ?? []);
  const names = agent.match.flatMap((m) => (m.argGlobs ? [] : (m.names ?? [])));
  if (!services.length || !(paths.length || names.length)) return undefined;
  const caller: Condition[] = [];
  if (paths.length) caller.push({ field: 'process.parentPath', op: 'glob', value: paths });
  if (names.length) caller.push({ field: 'process.parentName', op: 'in', value: names });
  // A short-lived shell often reaches Vigil without its parent's path; directly
  // under the agent itself, the tracker already identified that parent.
  if (agentId)
    caller.push({
      all: [
        { field: 'process.agent.id', op: 'eq', value: agentId },
        { field: 'process.agent.depth', op: 'eq', value: 1 },
      ],
    });
  const svc = String.raw`["']?(${services.map(escapeRe).join('|')})(-[0-9a-f]{8})?["']?`;
  return {
    all: [
      { field: 'process.name', op: 'in', value: ['security', 'sh', 'bash'] },
      { any: caller },
      {
        field: 'process.commandLine',
        op: 'regex',
        value: [
          String.raw`^((/bin/)?(ba)?sh -c )?(/usr/bin/)?security find-generic-password ` +
            String.raw`(?=[-\w .@"']{1,200}$)` +
            String.raw`(?=(.* )?-s ${svc}( |$))(?!.* -s .* -s )(?!(.* )?-[^asgw\s])`,
        ],
      },
    ],
  };
}

/** One exclusion per catalogue agent that keeps its sign-in in the keychain. */
const OWN_KEYCHAIN_LOGINS: Condition[] = AGENT_CATALOG.flatMap((a) => {
  const c = ownKeychainLogin(a);
  return c ? [c] : [];
});

/** Agent settings files, where hooks, permissions and MCP servers are configured. */
export const AGENT_CONFIG_RE = String.raw`(\.claude/settings[A-Za-z.]*\.json|\.claude\.json|\.codex/config\.toml|\.mcp\.json|\.cursor/(hooks|mcp)\.json|claude_desktop_config\.json)`;
/** A write verb (or redirect) landing on an agent settings file. Case-insensitive. */
export const CONFIG_WRITE_RE =
  String.raw`((^|[\s;&|(/])(tee|mv|cp|ln|rm|install|truncate|sponge)\s[^|;&]{0,200}?|>\|?\s*[^\s|;&<>]*)` +
  AGENT_CONFIG_RE;
/** An in-place edit (`sed -i`, `perl -i`) of an agent settings file. */
export const CONFIG_INPLACE_RE =
  String.raw`(sed\s+(-[a-zA-Z]*i|--in-place)|perl\s+-[a-zA-Z]*i)[^\n]{0,200}?` + AGENT_CONFIG_RE;
/** A script opening a file for writing; paired with AGENT_CONFIG_RE so it only counts on a settings file. */
export const SCRIPT_WRITE_RE = String.raw`(python3?|node|ruby|bun|deno)\s[^\n]{0,256}?(open\([^)]*['"][wax]|write_text|writeFile|fs\.write|File\.write)`;
/**
 * `claude|codex|gemini mcp add...`, which registers a new MCP server (a new
 * tool) without touching a file. Only where a command starts: the start, after
 * a separator, `$(`, a backtick, `sh -c` or `eval`, optionally by full path. The
 * same words printed or quoted as data (`printf '%s' claude mcp add …`) are not
 * a command.
 */
export const MCP_ADD_RE = String.raw`(^|[;&|(\x60\n]\s*|\s-c\s+["']?|\beval\s+["']?)(\S*/)?(claude|codex|gemini)\s+mcp\s+add(-json|-from-claude-desktop)?\b`;
export const AGENT_CONFIG_GLOBS = [
  '~/.claude/settings*.json',
  '**/.claude/settings*.json',
  '~/.claude.json',
  '**/.mcp.json',
  '~/.codex/config.toml',
  '~/.cursor/**',
  '**/.cursor/hooks.json',
  '**/.cursor/mcp.json',
  '~/Library/Application Support/Claude/claude_desktop_config.json',
];

// ------------------------------------------------------------ run downloaded
/**
 * Downloading code and running it straight away: curl/wget piped into a shell
 * or interpreter (an optional `sudo` and an absolute path allowed), or fed in
 * through process substitution. Case-insensitive. Used by the pre-flight pack.
 */
export const PREFLIGHT_PIPE_RE = String.raw`(curl|wget)\s[^|]*\|\s*(sudo(\s+-\S+)?(\s+-\S+)?\s+)?(\S*/)?((ba|z|da|k)?sh\b|(python[23]?|perl|ruby|node)\s*(-(\s|$)|$|[;&|)]))`;
export const PREFLIGHT_PROCSUB_RE = String.raw`(\b((ba|z|da|k)?sh|source|python[23]?|perl|ruby|node)|(^|[;&|(]\s*)\.)\s+(-\S+\s+)?<\(\s*(curl|wget)\b`;

/** One alert per agent session and command. */
const perCommand = (windowSec: number) => ({
  key: ['process.agent.session', 'process.commandLine'],
  windowSec,
});

export const agentWatchRules: DetectionRuleInput[] = [
  // ------------------------------------------------------------------ alert
  rule({
    id: 'agent-secret-read',
    name: 'AI agent opened a credential file',
    description:
      'An AI agent, or a program it started, opened cloud keys, an SSH private key, a token file, saved browser passwords or the keychain. The tools that use these files (aws, ssh, git, docker...) are left out.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['file'],
    // Depth 0 counts: the agent's own Read tool opens files as the agent.
    condition: {
      all: [
        AGENT,
        { field: 'op', op: 'in', value: ['open', 'write', 'rename'] },
        { field: 'path', op: 'glob', value: SECRET_FILE_GLOBS },
      ],
    },
    exclusions: [
      {
        field: 'process.name',
        op: 'in',
        value: [
          'aws',
          'gcloud',
          'kubectl',
          'ssh',
          'ssh-add',
          'ssh-keygen',
          'git',
          'git-remote-https',
          'docker',
          'docker-credential-desktop',
          'docker-credential-osxkeychain',
          'az',
          'terraform',
          'gh',
        ],
      },
      { field: 'path', op: 'glob', value: ['~/.ssh/*.pub'] },
      // Codex (in the ChatGPT app) talks to OpenAI's own ChatGPT extension for Chrome
      // through its storage (seen on a real Mac, 2026-10-02; listed by OpenAI). It
      // opens the folder itself as well as the files in it (seen 2026-10-05), and
      // `/**` needs something after the slash, so the folder is listed too.
      {
        all: [
          { field: 'process.agent.id', op: 'in', value: ['codex', 'codex-app'] },
          {
            field: 'path',
            op: 'glob',
            value: [
              '~/Library/Application Support/Google/Chrome/*/Local Extension Settings/hehggadaopoacecdllhhajmbjkdcmajg',
              '~/Library/Application Support/Google/Chrome/*/Local Extension Settings/hehggadaopoacecdllhhajmbjkdcmajg/**',
            ],
          },
        ],
      },
      // Every program that uses the keychain opens its database: the agent itself,
      // `security`, git's credential helper. The items inside stay locked behind the
      // keychain's own checks. A program that copies or packs files opening it does count.
      {
        all: [
          { field: 'path', op: 'glob', value: ['~/Library/Keychains/**'] },
          { not: { field: 'process.name', op: 'in', value: KEYCHAIN_COPIERS } },
        ],
      },
    ],
    reasons: [
      '{{process.name}}, running under {{process.agent.id}}, opened {{path}}.',
      'Agents rarely need this file. Text hidden in a web page or a repository can tell one to read it.',
    ],
    dedupe: { key: ['process.agent.session', 'path'], windowSec: 3600 },
    tags: ['agent-watch', 'attack.credential_access', 'attack.t1552.001'],
  }),
  rule({
    id: 'agent-secret-command',
    name: 'AI agent ran a command that reads a credential file',
    description:
      "A command an AI agent ran prints, copies or packs a file holding cloud keys, an SSH private key, a token or the keychain's passwords.",
    mode: 'alert',
    severity: 'medium',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        AGENT,
        CHILD,
        via([...SECRET_READERS, 'ditto', 'rsync']),
        // A shell passes via() whatever it runs, so the reader must be in the command too.
        {
          any: [{ all: [cmdI(SECRET_READ_RE), cmdI(...SECRET_PATH_RES)] }, cmdI(KEYCHAIN_READ_RE)],
        },
      ],
    },
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      'The command reads a file that holds keys or tokens.',
    ],
    dedupe: perCommand(3600),
    tags: ['agent-watch', 'attack.credential_access', 'attack.t1552.001'],
  }),
  rule({
    id: 'agent-secret-upload',
    name: 'AI agent sending credentials off this Mac',
    description:
      'A command an AI agent ran sends a credential file, or every environment variable, to another computer (a curl upload, a pipe into nc, scp).',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        AGENT,
        CHILD,
        via(['curl', 'wget', 'nc', 'ncat', 'socat', 'scp', 'rsync', 'nscurl']),
        {
          any: [
            { all: [cmdI(...SECRET_PATH_RES), { any: [cmd(...UPLOAD_RES), cmdI(PIPE_SINK_RE)] }] },
            cmdI(...COPY_OUT_RES),
            cmdI(ENV_DUMP_RE),
          ],
        },
      ],
    },
    response: [SUSPEND],
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      'It sends keys or tokens to another computer. Pause it unless you asked for exactly this.',
    ],
    dedupe: perCommand(600),
    tags: ['agent-watch', 'attack.exfiltration', 'attack.t1048'],
  }),
  rule({
    id: 'agent-paste-upload',
    name: 'AI agent uploading to a paste or file-drop site',
    description:
      'A command an AI agent ran uploads data to a paste site, a file drop or a request catcher, a common way to take data out.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        AGENT,
        CHILD,
        via(['curl', 'wget', 'nc', 'nscurl']),
        cmd(...UPLOAD_RES),
        cmdI(PASTE_HOST_RE),
      ],
    },
    response: [SUSPEND],
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      'Paste and file-drop sites keep whatever is sent to them where anyone with the link can read it.',
    ],
    dedupe: perCommand(600),
    tags: ['agent-watch', 'attack.exfiltration', 'attack.t1567'],
  }),
  rule({
    id: 'agent-persistence-command',
    name: 'AI agent set something to run at login',
    description:
      'A command an AI agent ran loads a launch agent, installs a crontab, or writes into a LaunchAgents or LaunchDaemons folder.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        AGENT,
        CHILD,
        via([
          'launchctl',
          'crontab',
          'cp',
          'mv',
          'tee',
          'ln',
          'ditto',
          'rsync',
          'install',
          'curl',
          'wget',
          'defaults',
          'plutil',
        ]),
        cmdI(...PERSIST_RES),
      ],
    },
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      "What it sets up keeps running after the agent's session ends.",
    ],
    dedupe: perCommand(3600),
    tags: ['agent-watch', 'attack.persistence', 'attack.t1543.001'],
  }),
  rule({
    id: 'agent-guard-tamper',
    name: 'AI agent tampering with Vigil or macOS protections',
    description:
      'A command an AI agent ran stops Vigil or Santa, changes their files, turns off Gatekeeper or the firewall, or resets privacy permissions.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: { all: [AGENT, CHILD, tamper('process.commandLine')] },
    response: [SUSPEND],
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      'It would weaken the protections that watch the agent.',
    ],
    dedupe: perCommand(3600),
    tags: ['agent-watch', 'attack.defense_evasion', 'attack.t1562.001'],
  }),
  rule({
    id: 'agent-hook-config-edit',
    name: "AI agent changing an agent's settings",
    description:
      'A command an AI agent ran edits Claude Code, Codex, Cursor or MCP settings, or registers a new MCP server (claude mcp add), where hooks, permissions and MCP servers are configured.',
    mode: 'alert',
    severity: 'medium',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        AGENT,
        CHILD,
        {
          any: [
            cmdI(CONFIG_WRITE_RE, CONFIG_INPLACE_RE, MCP_ADD_RE),
            { all: [cmd(SCRIPT_WRITE_RE), cmd(AGENT_CONFIG_RE)] },
          ],
        },
      ],
    },
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      "These settings can switch off Vigil's pre-flight check or give the agent new tools.",
    ],
    dedupe: perCommand(3600),
    tags: ['agent-watch', 'attack.defense_evasion', 'attack.persistence'],
  }),
  rule({
    id: 'agent-keychain-secret',
    name: 'AI agent reading a keychain password',
    description:
      'A command an AI agent ran prints a saved password from the keychain (security find-generic-password -w) or exports keychain items.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [AGENT, CHILD, via(['security']), cmd(KEYCHAIN_SECRET_RE)],
    },
    // An agent signing itself in with its own saved login is not this.
    exclusions: OWN_KEYCHAIN_LOGINS,
    response: [SUSPEND],
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      'It prints a saved password where the agent can read it.',
    ],
    dedupe: perCommand(3600),
    tags: ['agent-watch', 'attack.credential_access', 'attack.t1555.001'],
  }),

  // ----------------------------------------------------------------- shadow
  rule({
    id: 'agent-escapes-tree',
    name: 'AI agent started something that outlives it',
    description:
      'A command an AI agent ran detaches from the agent (nohup, setsid, tmux or screen in the background, at, launchctl submit) or hands it to Terminal or AppleScript. Common for dev servers, so it only records.',
    mode: 'shadow',
    severity: 'medium',
    fidelity: 'low',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        AGENT,
        CHILD,
        cmd(
          String.raw`(^|[\s;&|(])(nohup|setsid|disown)\b`,
          String.raw`(screen\s+-[a-zA-Z]*d|tmux\s+new(-session)?\s[^|;&]*-d\b|\bat\s+(now|-f)\b)`,
          String.raw`(launchctl\s+(submit|asuser)\b|open\s+-a\s+"?(Terminal|iTerm)|osascript\b[^|;&]*do\s+(shell\s+)?script)`,
        ),
      ],
    },
    reasons: [
      '{{process.agent.id}} ran: {{process.commandLine}}',
      "What it starts may no longer be tracked as the agent's.",
    ],
    dedupe: perCommand(3600),
    tags: ['agent-watch', 'attack.defense_evasion'],
  }),
  rule({
    id: 'agent-unsigned-first-exec',
    name: 'AI agent ran a new unsigned program from a download or temp folder',
    description:
      'An AI agent started an unsigned program from a temporary or Downloads folder for the first time. Agents build and fetch tools often, so it only records.',
    mode: 'shadow',
    severity: 'medium',
    fidelity: 'low',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        AGENT,
        CHILD,
        { field: 'process.signing', op: 'in', value: UNTRUSTED_SIGNING },
        {
          field: 'process.path',
          op: 'glob',
          value: ['/tmp/**', '/private/tmp/**', '/private/var/folders/**', '~/Downloads/**'],
        },
        { firstSeen: { key: ['process.path'] } },
      ],
    },
    reasons: [
      '{{process.agent.id}} started {{process.path}}, which is not signed.',
      'It is the first time this program ran on this Mac.',
    ],
    tags: ['agent-watch', 'attack.execution'],
  }),
  rule({
    id: 'vigil-ai-spawned-process',
    name: "Vigil's own AI helper started a program",
    description:
      "Vigil's explainer, labeller and rule reviewer run with every tool switched off, so a shell, script or downloader below them means something went wrong. Recorded only, for now.",
    mode: 'shadow',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        { field: 'process.agent.id', op: 'eq', value: 'vigil-self' },
        // Depth 1 is the helper itself (claude, codex); depth 2 is what it starts.
        { field: 'process.agent.depth', op: 'gt', value: 1 },
        {
          field: 'process.name',
          op: 'in',
          value: [...SCRIPT_RUNNERS, 'wget', 'nc', 'scp', 'node', 'npx', 'uvx'],
        },
      ],
    },
    reasons: [
      "{{process.parentName|'An AI helper'}} started {{process.commandLine}} under Vigil.",
      "Vigil's AI helpers have no tools, so they should never start programs.",
    ],
    dedupe: perCommand(3600),
    tags: ['agent-watch', 'attack.execution'],
  }),
];
