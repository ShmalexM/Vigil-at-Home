// Starting points for tool-call policy rules (Agents › Tool policy › New tool
// rule). Each one fills the rule editor with a draft that you check against
// the requests Vigil has stored, then save. Nothing here saves or runs a rule.
//
// They are ordinary rules on `agent.tool_request`: a rule in Ask mode makes
// Claude Code ask you before the step runs, Deny stops it, Record only logs.
// Rules decide, never an AI, and no rule can answer "allow".

/** A value a template needs before it can open, such as a domain. */
export interface TemplateInput {
  label: string;
  placeholder: string;
  /** Cleans what was typed (strips `https://`, say); undefined when it can't be used. */
  clean(raw: string): string | undefined;
  /** Shown when `clean` refuses. */
  hint: string;
}

export interface ToolRuleTemplate {
  id: string;
  title: string;
  description: string;
  input?: TemplateInput;
  /** The draft rule as editor JSON, with an id not in `taken`. */
  json(taken: ReadonlySet<string>, value?: string): string;
}

const WRITES = ['Write', 'Edit', 'MultiEdit', 'NotebookEdit'];
const RULE_ID = /^[a-z0-9][a-z0-9-]*$/;

/** `base`, or `base-2`, `base-3`… when you already have a rule by that id. */
export function uniqueRuleId(base: string, taken: ReadonlySet<string>): string {
  let id = base;
  for (let i = 2; taken.has(id); i++) id = `${base}-${i}`;
  return id;
}

const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40)
    .replace(/-+$/, '');

interface Draft {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
  fidelity: 'low' | 'medium' | 'high';
  condition: unknown;
  reasons: string[];
}

/** The editor's JSON for a tool rule: Ask mode, no actions, tagged so the AI never tunes it. */
function ruleJson(d: Draft, taken: ReadonlySet<string>): string {
  const id = uniqueRuleId(RULE_ID.test(d.id) ? d.id : 'tool-rule', taken);
  return JSON.stringify(
    {
      id,
      name: d.name,
      description: d.description,
      mode: 'alert',
      severity: d.severity,
      fidelity: d.fidelity,
      eventKinds: ['agent.tool_request'],
      condition: d.condition,
      exclusions: [],
      response: [],
      reasons: d.reasons,
      tags: ['agent-preflight'],
    },
    null,
    2,
  );
}

const MCP_SERVER = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const DOMAIN = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/;
/** MAX_REGEX_LENGTH in @vigil/detection (not imported, to keep it out of the renderer). */
const MAX_REGEX_LENGTH = 256;

/**
 * A URL whose host is `domain` or one of its subdomains, however the rest is
 * written: a login (`u@`), a port, a trailing dot, or a query or fragment
 * straight after the host. The host ends at the first `/`, `?`, `#` or `\`
 * (which browsers read as `/`), so `example.com@evil.test` and
 * `evil.test?.example.com` don't count. No nested quantifier, so it stays cheap.
 */
export function domainUrlRegex(domain: string): string {
  const esc = domain.replace(/\./g, '\\.');
  return String.raw`^https?://([^/?#@]*@)?([^/?#@:]*\.)?` + esc + String.raw`\.?(:\d*)?([/?#\\]|$)`;
}

export const TOOL_RULE_TEMPLATES: readonly ToolRuleTemplate[] = [
  {
    id: 'force-push',
    title: 'Ask before force-push',
    description: 'A git push with -f, --force or a +refspec can overwrite work on the remote.',
    json: (taken) =>
      ruleJson(
        {
          id: 'ask-force-push',
          name: 'Agent wants to force-push',
          description: 'Before a Bash step runs: the command force-pushes to a git remote.',
          severity: 'medium',
          fidelity: 'high',
          // `git`, any global options (`-C dir`, `-c k=v`, `--no-pager`), `push`, then
          // in the same command a short-flag cluster with f (-f, -uf), --force… or a
          // +refspec. Each option reads only one way, so it never backtracks badly.
          condition: {
            field: 'command',
            op: 'regex',
            value: String.raw`\bgit(?:\s+-[Cc]\s+\S+|\s+(?!-[Cc]\s)--?[a-z][\w-]*(?:=\S*)?)*\s+push\b[^|;&\n]*?(?:\s-[a-zA-Z]*f|\s--force|\s\+\S)`,
          },
          reasons: ['The command force-pushes, which can overwrite commits on the remote.'],
        },
        taken,
      ),
  },
  {
    id: 'outside-project',
    title: 'Ask before writes outside the project',
    description: 'Write and Edit steps on files outside the folder the agent was started in.',
    json: (taken) =>
      ruleJson(
        {
          id: 'ask-write-outside-project',
          name: 'Agent wants to write outside its project',
          description:
            'Before a Write or Edit step runs: the file is outside the folder the agent works in.',
          severity: 'medium',
          fidelity: 'medium',
          condition: {
            all: [
              { field: 'tool', op: 'in', value: WRITES },
              { field: 'toolOutsideCwd', op: 'eq', value: true },
            ],
          },
          reasons: ['{{tool}} would change {{filePath}}, outside {{cwd}}.'],
        },
        taken,
      ),
  },
  {
    id: 'mcp-server',
    title: 'Ask before any tool from an MCP server',
    description: 'Every tool call to one MCP server you name, as Claude Code names it.',
    input: {
      label: 'MCP server',
      placeholder: 'github',
      hint: 'Use the server’s name as it appears in its tools, like github in mcp__github__create_issue.',
      clean: (raw) => {
        const v =
          raw
            .trim()
            .replace(/^mcp__/, '')
            .split('__')[0] ?? '';
        return MCP_SERVER.test(v) ? v : undefined;
      },
    },
    json: (taken, server = 'example') =>
      ruleJson(
        {
          id: `ask-mcp-${slug(server) || 'server'}`,
          name: `Agent wants to use the ${server} MCP server`,
          description: `Before any tool from the ${server} MCP server runs.`,
          severity: 'low',
          fidelity: 'high',
          condition: { field: 'mcpServer', op: 'eq', value: server },
          reasons: ['{{tool}} comes from the {{mcpServer}} MCP server.'],
        },
        taken,
      ),
  },
  {
    id: 'domain',
    title: 'Ask before fetching a domain',
    description: 'WebFetch and other URL steps to one site and its subdomains.',
    input: {
      label: 'Domain',
      placeholder: 'example.com',
      hint: 'A domain like example.com, without a path.',
      clean: (raw) => {
        const v = raw
          .trim()
          .toLowerCase()
          .replace(/^[a-z]+:\/\//, '')
          .replace(/^\*\./, '')
          .replace(/[/?#].*$/, '');
        return DOMAIN.test(v) && domainUrlRegex(v).length <= MAX_REGEX_LENGTH ? v : undefined;
      },
    },
    json: (taken, domain = 'example.com') =>
      ruleJson(
        {
          id: `ask-fetch-${slug(domain) || 'domain'}`,
          name: `Agent wants to fetch from ${domain}`,
          description: `Before a step fetches a page from ${domain} or one of its subdomains.`,
          severity: 'low',
          fidelity: 'high',
          condition: { field: 'url', op: 'regex', nocase: true, value: [domainUrlRegex(domain)] },
          reasons: ['{{tool}} would fetch {{url}}.'],
        },
        taken,
      ),
  },
];
