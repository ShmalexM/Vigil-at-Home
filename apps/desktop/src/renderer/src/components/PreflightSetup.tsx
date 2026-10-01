import { Copy } from 'lucide-react';
import { useState } from 'react';
import { hookConnected, type AgentPrefs, type PreflightStatus } from '../../../shared/agents';
import { useLive, vigil } from '../api';
import { timeAgo } from '../format';
import { plural } from '../views/agents-format';
import { useToast } from './Toasts';
import { Button, Segmented, StatusMark, type MarkState } from './ui';

type HookState = 'off' | 'error' | 'connected' | 'waiting';

const STATE: Record<HookState, [MarkState, string]> = {
  off: ['pending', 'Off'],
  error: ['failed', 'Error'],
  connected: ['done', 'Connected'],
  waiting: ['warn', 'Not seen yet'],
};

function hookState(prefs: AgentPrefs, s: PreflightStatus, now: number): HookState {
  if (!prefs.preflightEnabled) return 'off';
  if (s.endpoint === 'error') return 'error';
  return hookConnected(s, now) ? 'connected' : 'waiting';
}

/**
 * Claude Code's pre-flight hook: the switch that opens Vigil's socket, the
 * hooks to paste into Claude Code (Vigil never writes Claude Code's files),
 * whether the hook has been heard from, and what happens when Vigil can't
 * answer. Used on Agents › Tool policy and as a setup step (`compact`).
 */
export function PreflightSetup({ compact }: { compact?: boolean }) {
  const toast = useToast();
  const [prefs, reloadPrefs] = useLive(() => vigil.getAgentPrefs());
  const [status, reloadStatus] = useLive(() => vigil.getPreflightStatus());
  // Once the hook is connected the hooks fold away, one click from being copied again.
  const [showHooks, setShowHooks] = useState(false);
  if (!prefs || !status) return null;

  const set = async (patch: Partial<AgentPrefs>) => {
    await vigil.setAgentPrefs(patch);
    reloadPrefs();
    reloadStatus();
  };
  const now = Date.now();
  const state = hookState(prefs, status, now);
  const [mark, label] = STATE[state];
  const last = Math.max(status.lastHelloAt ?? 0, status.lastRequestAt ?? 0);
  const detail = {
    off: 'Vigil isn’t answering. Turn it on, then add the hooks to Claude Code.',
    error: `Vigil couldn’t open its socket: ${status.error ?? 'unknown error'}`,
    connected: `The hook last checked in ${timeAgo(last, now)}.`,
    waiting: last
      ? `Vigil is listening. The hook last checked in ${timeAgo(last, now)}, more than a week ago.`
      : 'Vigil is listening. Add the hooks to Claude Code and start a new session.',
  }[state];
  const c = status.counts24h;

  return (
    <div className="col preflight" style={{ gap: 12 }}>
      <div className="row spread" style={{ alignItems: 'flex-start' }}>
        {compact ? (
          // The setup step shows its own done mark; here only the switch and what's missing.
          <div className="col" style={{ gap: 2 }}>
            <span className="t-h3">Answer Claude Code’s pre-flight checks</span>
            {state !== 'connected' && <span className="t-small">{detail}</span>}
          </div>
        ) : (
          <div className="row" style={{ alignItems: 'flex-start', gap: 10 }}>
            <StatusMark state={mark} label={label} />
            <div className="col" style={{ gap: 2 }}>
              <span className="t-h3">{label}</span>
              <span className="t-small">{detail}</span>
            </div>
          </div>
        )}
        <Segmented
          label="Pre-flight checks"
          value={prefs.preflightEnabled ? 'on' : 'off'}
          options={[
            { value: 'off', label: 'Off' },
            { value: 'on', label: 'On' },
          ]}
          onChange={(v) => void set({ preflightEnabled: v === 'on' })}
        />
      </div>

      {!compact && (
        <span className="t-small">
          Claude Code’s hook asks Vigil before a Bash, Write, Edit, Read, WebFetch or MCP step runs.
          Vigil’s rules answer: Deny stops the step, Ask hands it to you, and anything else is left
          to Claude Code as usual. Rules decide, never an AI, and Vigil never answers “allow”.
        </span>
      )}

      {prefs.preflightEnabled && state === 'connected' && !showHooks && (
        <div className="row">
          <Button size="sm" kind="ghost" onClick={() => setShowHooks(true)}>
            Show the hooks again
          </Button>
        </div>
      )}
      {prefs.preflightEnabled &&
        (state !== 'connected' || showHooks) &&
        (status.snippet ? (
          <div className="col" style={{ gap: 8 }}>
            <ol className="preflight-steps">
              <li>
                Copy these hooks into your Claude Code settings: <code>settings.json</code> in{' '}
                <code>~/.claude</code>, or in a project’s <code>.claude</code> folder. Vigil never
                opens that file.
              </li>
              <li>Restart your Claude Code sessions so they load the hooks.</li>
              <li>Vigil shows Connected once a session says hello.</li>
            </ol>
            <div className="snippet">
              <pre className="mono">{status.snippet}</pre>
              <Button
                size="sm"
                kind="ghost"
                icon={<Copy size={14} />}
                aria-label="Copy the hooks"
                onClick={async () => {
                  await navigator.clipboard.writeText(status.snippet);
                  toast({ text: 'Copied. Paste it into your Claude Code settings.' });
                }}
              >
                Copy
              </Button>
            </div>
          </div>
        ) : (
          <div className="attn fair">
            This build of Vigil doesn’t include the hook, so there is nothing to paste yet.
          </div>
        ))}

      <div className="row spread preflight-option">
        <div className="col" style={{ gap: 2 }}>
          <span className="t-h3">If Vigil can’t answer</span>
          <span className="t-small">
            {prefs.onUnavailable === 'ask'
              ? 'When Vigil is closed or too slow, Claude Code asks you before the step.'
              : 'When Vigil is closed or too slow, Claude Code decides as if Vigil weren’t there.'}{' '}
            The hooks carry this choice, so copy them again after changing it.
          </span>
        </div>
        <Segmented
          label="If Vigil can’t answer"
          value={prefs.onUnavailable}
          options={[
            { value: 'ask', label: 'Ask me' },
            { value: 'defer', label: 'Let Claude Code decide' },
          ]}
          onChange={(v) => void set({ onUnavailable: v })}
        />
      </div>

      {!prefs.preflightEnabled && last > 0 && (
        <span className="t-small warn-text">
          If the hooks are still in Claude Code, it treats every step as “Vigil can’t answer” while
          this is off. Remove them, or turn this back on.
        </span>
      )}

      {!compact && (
        <span className="t-small">
          Last 24 hours: {plural(c.deny, 'step')} stopped, {plural(c.ask, 'step')} asked,{' '}
          {plural(c.none, 'step')} left to Claude Code.
          {status.notRecorded > 0 &&
            ` Since Vigil started, ${plural(status.notRecorded, 'request')} over the storage limit ${status.notRecorded === 1 ? 'was' : 'were'} answered but not kept.`}
        </span>
      )}
    </div>
  );
}
