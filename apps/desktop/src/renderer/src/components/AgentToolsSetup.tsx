import { Copy } from 'lucide-react';
import { Fragment, useState, type ReactNode } from 'react';
import type { AgentToolsStatus, McpSnippets } from '../../../shared/agents';
import { useLive, vigil } from '../api';
import { timeAgo } from '../format';
import { plural } from '../views/agents-format';
import { useToast } from './Toasts';
import { Button, Segmented, StatusMark, type MarkState } from './ui';
import { computer } from '../platform';

type Where = keyof McpSnippets;

/** Where the MCP server entry goes, and what to do with it. */
const WHERE: Record<Where, { label: string; how: ReactNode; copied: string }> = {
  claudeCommand: {
    label: 'Claude Code',
    how: (
      <>
        Run this in Terminal, in the project you want it in. Add <code>--scope user</code> after{' '}
        <code>add-json</code> to have it in every project. Then start a new Claude Code session.
      </>
    ),
    copied: 'Copied. Run it in Terminal.',
  },
  mcpJson: {
    label: '.mcp.json',
    how: (
      <>
        For a project’s <code>.mcp.json</code> (Claude Code) or Cursor’s <code>mcp.json</code>. If
        the file already lists servers, add the <code>vigil</code> entry next to them.
      </>
    ),
    copied: 'Copied. Paste it into the mcp.json file.',
  },
  codexToml: {
    label: 'Codex',
    how: (
      <>
        Add this to Codex’s <code>config.toml</code> in <code>~/.codex</code>, then start a new
        Codex session.
      </>
    ),
    copied: 'Copied. Paste it into Codex’s config.toml.',
  },
};

function state(s: AgentToolsStatus): [MarkState, string, string] {
  if (!s.enabled) {
    return ['pending', 'Off', 'Agents that call Vigil’s tools are turned away.'];
  }
  if (s.endpoint === 'error') {
    return ['failed', 'Error', `Vigil couldn’t open its socket: ${s.error ?? 'unknown error'}`];
  }
  if (s.lastCallAt === undefined) {
    return ['warn', 'On', 'Add Vigil to your agent below. No agent has called yet.'];
  }
  return [
    'done',
    'On',
    `${plural(s.calls, 'call')} so far. The last, ${s.lastTool ?? 'a tool'}, ${timeAgo(s.lastCallAt)}.`,
  ];
}

/**
 * Vigil as a read-only MCP server for the user's own agents: the switch, the
 * entry to add to Claude Code, Cursor or Codex (Vigil never writes their
 * files), the tools an agent gets, and when they were last used.
 */
export function AgentToolsSetup() {
  const toast = useToast();
  const [status, reload] = useLive(() => vigil.getAgentToolsStatus(), null, 'agents');
  const [where, setWhere] = useState<Where>('claudeCommand');
  if (!status) return null;

  const set = async (on: boolean) => {
    await vigil.setAgentPrefs({ toolsEnabled: on });
    reload();
  };
  const [mark, label, detail] = state(status);
  const snippet = status.snippets?.[where];

  return (
    <div className="col agent-tools" style={{ gap: 12 }}>
      <div className="row spread" style={{ alignItems: 'flex-start' }}>
        <div className="row" style={{ alignItems: 'flex-start', gap: 10 }}>
          <StatusMark state={mark} label={label} />
          <div className="col" style={{ gap: 2 }}>
            <span className="t-h3">{label}</span>
            <span className="t-small">{detail}</span>
          </div>
        </div>
        <Segmented
          label="Vigil tools for your agents"
          value={status.enabled ? 'on' : 'off'}
          options={[
            { value: 'off', label: 'Off' },
            { value: 'on', label: 'On' },
          ]}
          onChange={(v) => void set(v === 'on')}
        />
      </div>

      <span className="t-small">
        Add Vigil as an MCP server to Claude Code, Cursor or Codex, and your agent can look up
        Vigil’s alerts, what it saw in the last 7 days and the agent sessions on this {computer},
        for example to explain an alert or check its own work. What it gets is redacted the way
        Vigil’s own AI gets it: names in home folder paths, keys and tokens are replaced. Vigil runs
        no model for this. No tool changes a rule, a setting or a block, and none shows how a rule
        works.
      </span>

      {status.enabled &&
        (status.snippets && snippet ? (
          <div className="col" style={{ gap: 8 }}>
            <div className="row">
              <Segmented
                label="Where to add Vigil"
                value={where}
                options={(Object.keys(WHERE) as Where[]).map((w) => ({
                  value: w,
                  label: WHERE[w].label,
                }))}
                onChange={setWhere}
              />
            </div>
            <span className="t-small">{WHERE[where].how}</span>
            <div className="snippet">
              <pre className="mono">{snippet}</pre>
              <Button
                size="sm"
                kind="ghost"
                icon={<Copy size={14} />}
                aria-label={`Copy the ${WHERE[where].label} entry`}
                onClick={async () => {
                  await navigator.clipboard.writeText(snippet);
                  toast({ text: WHERE[where].copied });
                }}
              >
                Copy
              </Button>
            </div>
            <span className="t-small">
              Vigil never opens these files. The tools answer only while this is on and Vigil is
              running, at most 120 calls a minute.
            </span>
          </div>
        ) : (
          <div className="attn fair">
            This build of Vigil doesn’t include the hook, so there is nothing to add yet.
          </div>
        ))}

      <div className="col" style={{ gap: 6 }}>
        <span className="t-h3">What your agent can call</span>
        <dl className="kv agent-tool-list">
          {status.tools.map((t) => (
            <Fragment key={t.name}>
              <dt>
                <code className="mono helper-tool">{t.name}</code>
              </dt>
              <dd>
                {t.description}
                {t.args && <span className="agent-tool-args"> ({t.args})</span>}
              </dd>
            </Fragment>
          ))}
        </dl>
      </div>

      {!status.enabled && status.refused > 0 && (
        <span className="t-small warn-text">
          Since Vigil started, an agent asked for its tools {plural(status.refused, 'time')} while
          they were off.
        </span>
      )}
    </div>
  );
}
