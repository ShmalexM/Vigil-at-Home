import { ExternalLink, KeyRound } from 'lucide-react';
import { useState } from 'react';
import { useLive, vigil } from '../api';
import { Button, Chip, SectionHead } from '../components/ui';
import { cleanError } from './onboarding/ApiKeys';
import './onboarding/onboarding.css';

/**
 * The threat feeds card. Feodo Tracker needs nothing; URLhaus and
 * MalwareBazaar need the user's own free abuse.ch Auth-Key, and stay off
 * (keeping what they already listed) until one is added.
 */
export function ThreatFeedsSection() {
  const [view, reload] = useLive(() => vigil.getFeedKeys());
  const [key, setKey] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const head = (
    <SectionHead
      title="Threat feeds"
      sub="Lists of known malware servers and files from abuse.ch, refreshed in the background."
    />
  );
  if (!view) return head;
  const saved = view.saved.abusech;
  const disabled = !view.canSave;

  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await vigil.saveFeedKey('abusech', key);
      setKey('');
      reload();
    } catch (err) {
      setError(cleanError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      {head}
      <div className="key-row">
        <div className="row spread" style={{ alignItems: 'flex-start' }}>
          <div className="col" style={{ gap: 3 }}>
            <div className="row" style={{ gap: 8 }}>
              <KeyRound size={15} aria-hidden />
              <span className="t-h3">abuse.ch Auth-Key</span>
              {saved && <Chip tone="good">Saved</Chip>}
            </div>
            <span className="t-small">
              {saved
                ? 'URLhaus and MalwareBazaar feeds are on. The key is free for non-commercial use.'
                : 'URLhaus and MalwareBazaar feeds are off until you add a free abuse.ch Auth-Key.'}
            </span>
          </div>
          <a
            className="btn sm ghost"
            href="https://auth.abuse.ch/"
            target="_blank"
            rel="noreferrer"
          >
            <ExternalLink size={14} />
            Get a key
          </a>
        </div>
        <form
          className="row key-form"
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <input
            className="input grow"
            type="password"
            autoComplete="off"
            spellCheck={false}
            placeholder={saved ? 'Paste a new key to replace it' : 'Paste your key'}
            aria-label="abuse.ch Auth-Key"
            value={key}
            disabled={disabled}
            onChange={(e) => setKey(e.target.value)}
          />
          <Button type="submit" kind="primary" size="sm" disabled={disabled || busy || !key.trim()}>
            Save
          </Button>
          {saved && (
            <Button
              kind="ghost"
              size="sm"
              onClick={async () => {
                await vigil.clearFeedKey('abusech');
                reload();
              }}
            >
              Remove
            </Button>
          )}
        </form>
        {disabled && (
          <span className="t-small">
            The Keychain isn’t available, so the key can’t be saved safely right now.
          </span>
        )}
        {error && (
          <span className="t-small" role="alert" style={{ color: 'var(--poor)' }}>
            {error}
          </span>
        )}
      </div>
    </>
  );
}
