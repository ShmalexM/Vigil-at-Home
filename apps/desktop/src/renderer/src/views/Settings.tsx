import { useEffect } from 'react';
import { BellRing, Wrench } from 'lucide-react';
import { useLive, vigil } from '../api';
import { useToast } from '../components/Toasts';
import { Button, Card, SectionHead } from '../components/ui';
import { AppearanceSection } from './Appearance';
import { PageHead } from './AppShell';

export function SettingsView() {
  const [settings, reload] = useLive(() => vigil.getSettings());
  const toast = useToast();
  // The theme can change from another window too.
  useEffect(() => vigil.on('theme', reload), [reload]);
  if (!settings) return null;

  return (
    <div className="page">
      <PageHead title="Settings" purpose="How Vigil looks and behaves on this Mac." />
      <Card>
        <AppearanceSection
          theme={settings.theme}
          saved={settings.appearance}
          onTheme={async (t) => {
            await vigil.setTheme(t);
            reload();
          }}
        />
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
        <SectionHead
          title="Setup"
          sub="Walk through installing protection and connecting AI again, or switch between local, cloud and both. Saved keys are kept."
          right={
            <Button
              icon={<Wrench size={15} />}
              onClick={async () => {
                await vigil.restartSetup();
                location.hash = 'setup';
              }}
            >
              Run setup again
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
