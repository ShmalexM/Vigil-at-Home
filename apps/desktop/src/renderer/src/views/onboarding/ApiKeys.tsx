import { ExternalLink, KeyRound } from 'lucide-react';
import { useState } from 'react';
import type { ApiKeyView, SetupView } from '../../../../shared/setup';
import { vigil } from '../../api';
import { onLinux } from '../../platform';
import { Button, Card, Chip, SectionHead } from '../../components/ui';

/** Electron wraps errors from main as "Error invoking remote method '…': Error: <message>". */
export function cleanError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  return msg.replace(/^Error invoking remote method '[^']+': (\w*Error: )?/, '');
}

export function ApiKeys({ view, setView }: { view: SetupView; setView: (v: SetupView) => void }) {
  const main = view.keys.filter((k) => !k.more);
  const more = view.keys.filter((k) => k.more);
  const row = (k: ApiKeyView) => (
    <KeyRow key={k.provider} k={k} disabled={!view.canSaveKeys} setView={setView} />
  );
  return (
    <Card>
      <SectionHead
        title="API keys"
        sub={`Only needed if you don’t use Claude Code or Codex above, or want pay-per-use instead of your plan. Keys are encrypted with ${onLinux ? 'your desktop’s keyring' : 'your Mac’s Keychain'} and stay in Vigil’s main process; this window never sees them again.`}
      />
      {!view.canSaveKeys && (
        <div className="attn fair">
          The macOS Keychain isn’t available, so keys can’t be saved safely right now.
        </div>
      )}
      <div className="col" style={{ gap: 10 }}>
        {main.map(row)}
        {more.length > 0 && (
          // Open when one of these is already saved, so it's never hidden from the user.
          <details className="key-more" open={more.some((k) => k.saved) || undefined}>
            <summary className="t-small">More options</summary>
            <div className="col" style={{ gap: 10, marginTop: 10 }}>
              {more.map(row)}
            </div>
          </details>
        )}
      </div>
    </Card>
  );
}

function KeyRow({
  k,
  disabled,
  setView,
}: {
  k: ApiKeyView;
  disabled: boolean;
  setView: (v: SetupView) => void;
}) {
  const [key, setKey] = useState('');
  const [baseUrl, setBaseUrl] = useState(k.baseUrl ?? '');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      setView(
        await vigil.saveApiKey({
          provider: k.provider,
          key,
          ...(k.needsBaseUrl && baseUrl ? { baseUrl } : {}),
        }),
      );
      setKey('');
    } catch (err) {
      setError(cleanError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="key-row">
      <div className="row spread" style={{ alignItems: 'flex-start' }}>
        <div className="col" style={{ gap: 3 }}>
          <div className="row" style={{ gap: 8 }}>
            <KeyRound size={15} aria-hidden />
            <span className="t-h3">{k.name}</span>
            {k.saved && <Chip tone="good">Saved ••••{k.saved}</Chip>}
          </div>
          <span className="t-small">{k.use}</span>
        </div>
        {k.url && (
          <a className="btn sm ghost" href={k.url} target="_blank" rel="noreferrer">
            <ExternalLink size={14} />
            Get a key
          </a>
        )}
      </div>
      <form
        className="row key-form"
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        {k.needsBaseUrl && (
          <input
            className="input"
            type="url"
            placeholder="https://gateway.example.com/v1"
            aria-label={`${k.name} address`}
            value={baseUrl}
            disabled={disabled}
            onChange={(e) => setBaseUrl(e.target.value)}
          />
        )}
        <input
          className="input grow"
          type="password"
          autoComplete="off"
          spellCheck={false}
          placeholder={k.saved ? 'Paste a new key to replace it' : 'Paste your key'}
          aria-label={`${k.name} key`}
          value={key}
          disabled={disabled}
          onChange={(e) => setKey(e.target.value)}
        />
        <Button type="submit" kind="primary" size="sm" disabled={disabled || busy || !key.trim()}>
          Save
        </Button>
        {k.saved && (
          <Button
            kind="ghost"
            size="sm"
            onClick={async () => setView(await vigil.clearApiKey(k.provider))}
          >
            Remove
          </Button>
        )}
      </form>
      {error && (
        <span className="t-small" role="alert" style={{ color: 'var(--poor)' }}>
          {error}
        </span>
      )}
    </div>
  );
}
