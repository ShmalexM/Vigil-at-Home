import { Download, ExternalLink, RefreshCw } from 'lucide-react';
import { useLive, vigil } from '../api';
import { Button, Segmented } from '../components/ui';
import { checkedAt } from './updates-format';

/**
 * Settings › About › Updates. Vigil isn't signed yet, so it can't install
 * updates itself: it checks GitHub for a newer release and offers the
 * installer (or, without one for this computer, the release page).
 */
export function UpdatesRow() {
  const [u, reload] = useLive(() => vigil.getUpdates());
  if (!u) return null;
  const status = u.checking
    ? 'Checking…'
    : u.error
      ? u.error
      : u.available
        ? `Version ${u.available.version} is available. You have ${u.current}.`
        : u.lastCheckedAt
          ? `Up to date, checked ${checkedAt(u.lastCheckedAt)}`
          : u.auto
            ? 'Not checked yet. Vigil checks a minute after it starts, then every 6 hours.'
            : 'Not checked yet. Press Check now.';
  return (
    <div className="col" style={{ gap: 8 }}>
      <span role="status">{status}</span>
      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
        {u.available && (
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
          label="Check for updates automatically"
          value={u.auto ? 'on' : 'off'}
          options={[
            { value: 'on', label: 'Check automatically' },
            { value: 'off', label: 'Only when I ask' },
          ]}
          onChange={async (v) => {
            await vigil.setUpdateAuto(v === 'on');
            reload();
          }}
        />
      </div>
      <span className="small muted">
        Vigil only looks at GitHub’s public list of releases and sends nothing about you. You run
        the installer yourself to update; automatic installs come once Vigil is signed.
      </span>
    </div>
  );
}
