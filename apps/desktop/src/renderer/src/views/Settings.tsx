import { BellRing } from 'lucide-react';
import type { ThemePref } from '../../../shared/ipc';
import { useLive, vigil } from '../api';
import { useToast } from '../components/Toasts';
import { Button, Card, SectionHead, Segmented } from '../components/ui';
import { PageHead } from './AppShell';

export function SettingsView() {
  const [settings, reload] = useLive(() => vigil.getSettings());
  const toast = useToast();
  if (!settings) return null;

  return (
    <div className="page">
      <PageHead title="Settings" purpose="How Vigil looks and behaves on this Mac." />
      <Card>
        <SectionHead title="Appearance" />
        <div className="row spread">
          <span>Theme</span>
          <Segmented<ThemePref>
            label="Theme"
            value={settings.theme}
            onChange={async (t) => {
              await vigil.setTheme(t);
              reload();
            }}
            options={[
              { value: 'system', label: 'System' },
              { value: 'dark', label: 'Dark' },
              { value: 'light', label: 'Light' },
            ]}
          />
        </div>
      </Card>
      <Card>
        <SectionHead
          title="Test the popup"
          sub="Shows a harmless test alert so you can see how Vigil gets your attention. Nothing is blocked."
          right={
            <Button
              icon={<BellRing size={15} />}
              onClick={async () => {
                await vigil.sendTestAlert();
                toast({ text: 'Test alert sent' });
              }}
            >
              Send a test alert
            </Button>
          }
        />
      </Card>
      <Card>
        <SectionHead title="About" />
        <dl className="kv">
          <dt>Version</dt>
          <dd>{settings.version}</dd>
          <dt>Data folder</dt>
          <dd className="mono">{settings.dataDir}</dd>
          <dt>License</dt>
          <dd>Apache-2.0, open source</dd>
        </dl>
      </Card>
    </div>
  );
}
