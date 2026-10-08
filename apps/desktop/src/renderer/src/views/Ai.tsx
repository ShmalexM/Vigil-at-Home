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
import { computer } from '../platform';

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
  local: `on this ${computer} only`,
  cloud: 'in the cloud',
  both: `on this ${computer} and in the cloud`,
};

/**
 * The AI card: which apps and keys explain alerts, which label events, and a
 * switch for each. Probing runs the vendors' CLIs, so it happens on open and
 * on Refresh, not on every change in the app.
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

  const row = (p: AiProviderView, view: AiView) => (
    <li key={p.provider} className="ai-row">
      <StatusMark state={MARK[p.state]} label={STATE_TEXT[p.state]} />
      <div className="ai-main">
        <div className="ai-name">
          {p.name}
          <Chip>{p.local ? `On this ${computer}` : 'Cloud'}</Chip>
        </div>
        <div className="ai-used">{usedFor(p, view)}</div>
        <div className="ai-sub">{describe(p, view)}</div>
        {p.provider === 'claude' && view.prefs.claude && (
          <div className="ai-plan">
            <Segmented
              label="Use my Claude plan"
              value={view.prefs.claudePlan ? 'on' : 'off'}
              options={[
                { value: 'off', label: 'Off' },
                { value: 'on', label: 'My Claude plan' },
              ]}
              onChange={(v) => void setPref({ claudePlan: v === 'on' })}
            />
            <span className="ai-sub">
              Your Claude plan is used only when you ask Vigil to explain an alert. Everything Vigil
              does on its own uses an Anthropic API key.
            </span>
          </div>
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
              void act(() => vigil.signInAi(p.provider), 'Finish signing in in your browser')
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
  );

  return (
    <>
      <SectionHead
        title="AI"
        sub={`Explains alerts and labels unusual events${view?.mode ? `, ${MODE_TEXT[view.mode]}` : ''}. None of it blocks or allows anything: rules do the blocking, and you decide. Change where it runs in Setup.`}
        right={
          <IconButton label="Check again" onClick={() => void load()} disabled={loading}>
            <RefreshCw size={15} className={loading ? 'spin' : undefined} />
          </IconButton>
        }
      />
      {!view ? (
        <p className="ai-sub ai-empty">Checking your AI apps…</p>
      ) : (
        <>
          <h4 className="ai-group">Explains alerts</h4>
          <p className="ai-sub ai-group-sub">
            When an alert comes in, Vigil asks the first app here that’s ready, top to bottom, to
            explain it in plain words.
          </p>
          <ul className="ai-list">
            {view.providers.filter((p) => p.provider !== 'jev').map((p) => row(p, view))}
          </ul>
          <h4 className="ai-group">Labels events no rule matched</h4>
          <p className="ai-sub ai-group-sub">
            {labellingText(view)} Hints only: nothing is blocked or allowed because of a label.
          </p>
          <div className="ai-option">
            <div className="ai-main">
              <div className="ai-name">Label events</div>
              <div className="ai-sub">
                Off stops sending events for labels. Alerts are still explained.
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
          <ul className="ai-list ai-list-bordered">
            {view.providers.filter((p) => p.provider === 'jev').map((p) => row(p, view))}
          </ul>
          <CapField cap={view.prefs.monthlyCapUsd} onSave={(c) => setPref({ monthlyCapUsd: c })} />
        </>
      )}
    </>
  );
}

/** Claude Haiku labels first when Claude is on with an Anthropic API key, outside local mode. */
function haikuLabels(view: AiView): boolean {
  return view.prefs.labelling && view.prefs.claude && view.anthropicKey && view.mode !== 'local';
}

/**
 * What Vigil uses this app or key for, given where AI runs. Mirrors the
 * routing in @vigil/ai: explanations go down the list in order; labels go to
 * Claude Haiku (with an Anthropic API key), then Jev, then the small local
 * model (or, cloud only, the other apps above).
 */
function usedFor(p: AiProviderView, view: AiView): string {
  const labels = view.prefs.labelling;
  const haiku = haikuLabels(view);
  const before = haiku ? (view.jevVia ? 'Claude Haiku and Jev' : 'Claude Haiku') : 'Jev';
  if (p.provider === 'jev')
    return haiku
      ? 'Used for: labelling events when Claude Haiku can’t. It never explains alerts.'
      : 'Used for: labelling events only. It never explains alerts.';
  if (p.provider === 'ollama') {
    if (view.mode === 'cloud') return 'Not used while Vigil runs AI in the cloud only.';
    const explain =
      view.mode === 'local' ? 'explaining alerts' : 'explaining alerts when nothing above is ready';
    if (!labels) return `Used for: ${explain}.`;
    return view.mode !== 'local' && (view.jevVia || haiku)
      ? `Used for: ${explain}, and labelling events with a small model when ${before} can’t.`
      : `Used for: ${explain}, and labelling events with a small model.`;
  }
  if (view.mode === 'local') return `Not used while Vigil runs AI on this ${computer} only.`;
  if (p.provider === 'claude') {
    if (!view.anthropicKey)
      return view.prefs.claudePlan
        ? 'Used for: explaining an alert when you ask, with your Claude plan.'
        : 'Not used yet: add an Anthropic API key in Setup, or turn on your Claude plan below.';
    return haiku
      ? 'Used for: explaining alerts, and labelling events with Claude Haiku.'
      : 'Used for: explaining alerts.';
  }
  return view.mode === 'cloud' && labels && (view.jevVia || haiku)
    ? `Used for: explaining alerts, and labelling events when ${before} can’t.`
    : view.mode === 'cloud' && labels
      ? 'Used for: explaining alerts and labelling events.'
      : 'Used for: explaining alerts.';
}

function labellingText(view: AiView): string {
  if (view.mode === 'local')
    return `A small model on this ${computer} labels unusual programs and connections in Activity.`;
  const fallback =
    view.mode === 'cloud'
      ? view.jevVia
        ? 'Jev, then the other apps above, take over'
        : 'The other apps above take over'
      : view.jevVia
        ? `Jev, then the model on this ${computer}, take over`
        : `The model on this ${computer} takes over`;
  if (haikuLabels(view))
    return `Claude Haiku labels unusual programs and connections in Activity, using your Anthropic API key. ${fallback} when it can’t.`;
  const addHaiku =
    view.prefs.claude && !view.anthropicKey
      ? ' An Anthropic API key would let Claude Haiku label first.'
      : '';
  if (view.jevVia)
    return `Jev labels unusual programs and connections in Activity. ${
      view.mode === 'cloud'
        ? 'The apps above take over'
        : `The model on this ${computer} takes over`
    } when it can’t.${addHaiku}`;
  return view.mode === 'cloud'
    ? `The apps above label unusual programs and connections in Activity, within their background share. An OpenRouter or TypeSafe key adds Jev.${addHaiku}`
    : `A small model on this ${computer} labels unusual programs and connections in Activity. An OpenRouter or TypeSafe key adds Jev.${addHaiku}`;
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
        Covers the cloud API, Jev, and Claude or Codex on an API key. Vigil stops using them for the
        month once it’s reached.
      </span>
    </form>
  );
}
