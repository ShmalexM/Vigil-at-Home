import { Download, RefreshCw } from 'lucide-react';
import { useLive, vigil } from '../api';
import { Button, Segmented } from '../components/ui';
import { computer } from '../platform';

/**
 * Settings › About › Updates. Vigil isn't signed yet, so it can't install
 * updates itself: it checks GitHub for a newer release and offers the DMG.
 */
export function UpdatesRow() {
  const [u, reload] = useLive(() => vigil.getUpdates());
  if (!u) return null;
  const status = u.checking
    ? 'Checking…'
    : u.error
      ? u.error
      : u.available
        ? `Version ${u.available.version} is available`
        : u.lastCheckedAt
          ? `Up to date, checked ${new Date(u.lastCheckedAt).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}`
          : 'Not checked yet';
  return (
    <div className="col" style={{ gap: 8 }}>
      <span>{status}</span>
      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
        {u.available && (
          <Button
            size="sm"
            kind="primary"
            icon={<Download size={14} />}
            onClick={() => void vigil.downloadUpdate()}
          >
            Download {u.available.version}
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
        Vigil downloads the installer for your {computer} from GitHub; you open it to update.
        Automatic installs come once Vigil is signed by Apple.
      </span>
    </div>
  );
}
