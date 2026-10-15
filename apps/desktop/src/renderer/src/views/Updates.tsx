import { Download, ExternalLink, RefreshCw, RotateCw } from 'lucide-react';
import { updateNeedsUser } from '../../../shared/updates';
import { useLive, vigil } from '../api';
import { Button, Segmented } from '../components/ui';
import { computer } from '../platform';
import { checkedAt } from './updates-format';

/**
 * Settings › About › Updates. On a Mac where it can, Vigil downloads, checks
 * and installs a newer release by itself while the user is away; otherwise
 * it offers the installer (or, without one for this computer, the release page).
 */
export function UpdatesRow() {
  const [u, reload] = useLive(() => vigil.getUpdates());
  if (!u) return null;
  const selfInstalls = u.selfInstall && u.install;
  const status = u.checking
    ? 'Checking…'
    : u.ready
      ? `Version ${u.ready} is downloaded and checked. It installs the next time you step away for a few minutes, or when Vigil quits.`
      : u.preparing
        ? `Getting version ${u.preparing} ready…`
        : u.installError
          ? `${u.installError}. You can still download it yourself.`
          : u.error
            ? u.error
            : u.available
              ? `Version ${u.available.version} is available. You have ${u.current}.`
              : u.lastCheckedAt
                ? `Up to date${u.updatedFrom ? ` (updated from ${u.updatedFrom})` : ''}, checked ${checkedAt(u.lastCheckedAt)}`
                : u.auto
                  ? 'Not checked yet. Vigil checks a minute after it starts, then every 6 hours.'
                  : 'Not checked yet. Press Check now.';
  return (
    <div className="col" style={{ gap: 8 }}>
      <span role="status">{status}</span>
      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
        {u.ready && (
          <Button
            size="sm"
            kind="primary"
            icon={<RotateCw size={14} />}
            onClick={() => void vigil.installUpdate()}
          >
            Restart now
          </Button>
        )}
        {u.available && updateNeedsUser(u) && (
          <Button
            size="sm"
            kind="primary"
            icon={<Download size={14} />}
            onClick={() => void vigil.downloadUpdate()}
          >
            {u.available.downloadUrl
              ? `Download ${u.available.version}`
              : `Get ${u.available.version} on GitHub`}
          </Button>
        )}
        {u.available?.downloadUrl && (
          <Button
            size="sm"
            kind="ghost"
            icon={<ExternalLink size={14} />}
            onClick={() => void vigil.openUpdateNotes()}
          >
            What’s new
          </Button>
        )}
        <Button
          size="sm"
          icon={<RefreshCw size={14} className={u.checking ? 'spin' : undefined} />}
          disabled={u.checking}
          onClick={async () => {
            await vigil.checkUpdates();
            reload();
          }}
        >
          Check now
        </Button>
        <Segmented
          label="Updates"
          value={!u.auto ? 'manual' : selfInstalls ? 'install' : 'notify'}
          options={[
            ...(u.selfInstall
              ? [{ value: 'install' as const, label: 'Install automatically' }]
              : []),
            { value: 'notify' as const, label: u.selfInstall ? 'Tell me' : 'Check automatically' },
            { value: 'manual' as const, label: 'Only when I ask' },
          ]}
          onChange={async (v) => {
            await vigil.setUpdateMode(v);
            reload();
          }}
        />
      </div>
      <span className="small muted">
        Vigil only looks at GitHub’s public list of releases and sends nothing about you.{' '}
        {u.selfInstall
          ? 'An update installs only if it matches the checksums published with its release. Blocking keeps running while Vigil restarts, and a new helper still asks for your password once.'
          : `You download the installer for your ${computer} and open it to update.`}
      </span>
    </div>
  );
}
