import { useCallback, useEffect, useState } from 'react';
import { LogIn, RefreshCw, Unlink } from 'lucide-react';
import type { AiPrefsPatch, AiProviderView, AiView } from '../../../shared/ai';
import { vigil } from '../api';
import '../styles/ai.css';
import { useToast } from '../components/Toasts';
import {
  Button,
  Chip,
  IconButton,
  SectionHead,
  Segmented,
  StatusMark,
  type MarkState,
} from '../components/ui';

const MARK: Record<AiProviderView['state'], MarkState> = {
  ready: 'done',
  needs_sign_in: 'warn',
  not_installed: 'pending',
  binary_changed: 'warn',
  needs_setup: 'warn',
  optional: 'pending',
  disabled: 'pending',
  paused_by_vigil: 'pending',
  error: 'failed',
};

const STATE_TEXT: Record<AiProviderView['state'], string> = {
  ready: 'Ready',
  needs_sign_in: 'Needs sign-in',
  not_installed: 'Not installed',
  binary_changed: 'Program changed since setup',
  needs_setup: 'Not set up',
  optional: 'Optional',
  disabled: 'Off',
  paused_by_vigil: 'Paused by a Vigil update',
  error: 'Not working',
};

const MODE_TEXT = {
  local: 'on this Mac only',
  cloud: 'in the cloud',
  both: 'on this Mac and in the cloud',
};

/**
 * The AI that explains alerts: which apps and keys Vigil uses, and switches
 * for each. Probing runs the vendors' CLIs, so it happens on open and on
 * Refresh, not on every change in the app.
 */
export function AiSection() {
  const [view, setView] = useState<AiView>();
  const [loading, setLoading] = useState(false);
  const toast = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setView(await vigil.getAi());
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => void load(), [load]);

  const setPref = async (patch: AiPrefsPatch) => {
    await vigil.setAiPrefs(patch);
    await load();
  };

  const act = async (run: () => Promise<{ ok: boolean; error?: string } | void>, done: string) => {
    const r = await run();
    if (r && !r.ok) toast({ text: r.error ?? 'That didn’t work' });
    else toast({ text: done });
    await load();
  };

  return (
    <>
      <SectionHead
        title="AI"
        sub={
          view?.mode
            ? `Explains alerts in plain words, ${MODE_TEXT[view.mode]}. It never blocks or allows anything; you decide. Change where it runs in Setup.`
            : 'Explains alerts in plain words. It never blocks or allows anything; you decide.'
        }
        right={
          <IconButton label="Check again" onClick={() => void load()} disabled={loading}>
            <RefreshCw size={15} className={loading ? 'spin' : undefined} />
          </IconButton>
        }
      />
      {!view ? (
        <p className="ai-sub ai-empty">Checking your AI apps…</p>
      ) : (
        <ul className="ai-list">
          {view.providers.map((p) => (
            <li key={p.provider} className="ai-row">
              <StatusMark state={MARK[p.state]} label={STATE_TEXT[p.state]} />
              <div className="ai-main">
                <div className="ai-name">
                  {p.name}
                  <Chip>{p.local ? 'On this Mac' : 'Cloud'}</Chip>
                </div>
                <div className="ai-sub">{describe(p, view)}</div>
                {p.provider === 'claude' && view.prefs.claude && (
                  <Segmented
                    label="How Claude is paid for"
                    value={view.prefs.claudeUses}
                    options={[
                      { value: 'subscription', label: 'My Claude plan' },
                      { value: 'apiKey', label: 'Anthropic API key' },
                    ]}
                    onChange={(v) => void setPref({ claudeUses: v })}
                  />
                )}
                {p.provider === 'codex' && view.prefs.codex && (
                  <Segmented
                    label="How Codex is paid for"
                    value={view.prefs.codexUses}
                    options={[
                      { value: 'subscription', label: 'My ChatGPT plan' },
                      { value: 'apiKey', label: 'OpenAI API key' },
                    ]}
                    onChange={(v) => void setPref({ codexUses: v })}
                  />
                )}
              </div>
              <div className="ai-actions">
                {p.canShareSignIn && !p.signInShared && (
                  <Button
                    size="sm"
                    kind="primary"
                    icon={<LogIn size={14} />}
                    onClick={() =>
                      void act(() => vigil.shareCodexSignIn(), 'Vigil now uses your Codex sign-in')
                    }
                  >
                    Use my Codex sign-in
                  </Button>
                )}
                {p.canSignIn && (
                  <Button
                    size="sm"
                    icon={<LogIn size={14} />}
                    onClick={() =>
                      void act(
                        () => vigil.signInAi(p.provider),
                        'Finish signing in in your browser',
                      )
                    }
                  >
                    Sign in
                  </Button>
                )}
                {p.signInShared && (
                  <Button
                    size="sm"
                    kind="ghost"
                    icon={<Unlink size={14} />}
                    onClick={() =>
                      void act(
                        () => vigil.stopSharingCodexSignIn(),
                        'Vigil stopped using your Codex sign-in',
                      )
                    }
                  >
                    Stop sharing
                  </Button>
                )}
                <Segmented
                  label={`Use ${p.name}`}
                  value={view.prefs[p.provider] ? 'on' : 'off'}
                  options={[
                    { value: 'on', label: 'On' },
                    { value: 'off', label: 'Off' },
                  ]}
                  onChange={(v) => void setPref({ [p.provider]: v === 'on' })}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
      {view && (
        <div className="ai-option">
          <div className="ai-main">
            <div className="ai-name">Label events no rule matched</div>
            <div className="ai-sub">
              {view.mode === 'local'
                ? 'A small model on this Mac marks unusual programs and connections in Activity.'
                : view.jevVia
                  ? 'Jev marks unusual programs and connections in Activity, with the model on this Mac as a fallback.'
                  : 'A small model on this Mac marks unusual programs and connections in Activity.'}{' '}
              Hints only: nothing is blocked or allowed because of a label.
            </div>
          </div>
          <Segmented
            label="Label events no rule matched"
            value={view.prefs.labelling ? 'on' : 'off'}
            options={[
              { value: 'on', label: 'On' },
              { value: 'off', label: 'Off' },
            ]}
            onChange={(v) => void setPref({ labelling: v === 'on' })}
          />
        </div>
      )}
      {view && (
        <CapField cap={view.prefs.monthlyCapUsd} onSave={(c) => setPref({ monthlyCapUsd: c })} />
      )}
    </>
  );
}

function describe(p: AiProviderView, view: AiView): string {
  const parts: string[] = [STATE_TEXT[p.state]];
  if (p.provider === 'api' && view.api) parts.push(`${view.api.name} key ending ${view.api.last4}`);
  if (p.provider === 'api' && !view.api)
    parts.push(
      view.jevVia === 'typesafe'
        ? 'Your TypeSafe key covers only Jev. An OpenRouter key in Setup would cover this and Jev'
        : 'Add an OpenRouter or OpenAI key in Setup to use it',
    );
  if (p.signInShared) parts.push('Using your own Codex sign-in');
  if (p.account) parts.push(p.account);
  if (p.version) parts.push(p.version);
  if (p.detail) parts.push(p.detail);
  return parts.join(' · ');
}

/** A monthly limit on what Vigil may spend on paid keys. Empty means no limit. */
function CapField({
  cap,
  onSave,
}: {
  cap: number | undefined;
  onSave: (c: number | null) => Promise<void>;
}) {
  const [text, setText] = useState(cap === undefined ? '' : String(cap));
  useEffect(() => setText(cap === undefined ? '' : String(cap)), [cap]);
  const value = text.trim() === '' ? null : Number(text);
  const valid = value === null || (Number.isFinite(value) && value >= 0 && value <= 10_000);
  const changed = value !== (cap ?? null);
  return (
    <form
      className="ai-cap"
      onSubmit={(e) => {
        e.preventDefault();
        if (valid && changed) void onSave(value);
      }}
    >
      <label htmlFor="ai-cap">Monthly limit for paid keys (US$)</label>
      <input
        id="ai-cap"
        className="field"
        inputMode="decimal"
        placeholder="No limit"
        value={text}
        aria-invalid={!valid || undefined}
        onChange={(e) => setText(e.target.value)}
      />
      <Button size="sm" type="submit" disabled={!valid || !changed}>
        Save
      </Button>
      <span className="ai-sub">
        Covers the cloud API, Jev and Claude on an API key. Vigil stops using them for the month
        once it’s reached.
      </span>
    </form>
  );
}
