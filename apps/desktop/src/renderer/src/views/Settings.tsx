import { useEffect } from 'react';
import { BellRing } from 'lucide-react';
import { useLive, vigil } from '../api';
import { AlertViewSwitch } from '../components/Attention';
import { useToast } from '../components/Toasts';
import { Button, Card, SectionHead } from '../components/ui';
import { AiSection } from './Ai';
import { AppearanceSection } from './Appearance';
import { UpdatesRow } from './Updates';
import { PageHead } from './AppShell';
import { SetupPanel } from './onboarding/SetupPanel';

export function SettingsView() {
  const [settings, reload] = useLive(() => vigil.getSettings());
  const [status] = useLive(() => vigil.getStatus());
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
      {status && (
        <Card>
          <SectionHead
            title="Alerts"
            sub="Show me less lists only what needs your decision and folds the rest into one line. Show me more lists everything Vigil noticed and counts it on the menu-bar icon. What Vigil blocks is the same either way."
          />
          <div className="row spread">
            <span>How much to show</span>
            <AlertViewSwitch value={status.alertView} />
          </div>
        </Card>
      )}
      <Card>
        <AiSection />
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
      <SetupPanel />
      <Card>
        <SectionHead title="About" />
        <dl className="kv">
          <dt>Version</dt>
          <dd>{settings.version}</dd>
          <dt>Updates</dt>
          <dd>
            <UpdatesRow />
          </dd>
          <dt>Data folder</dt>
          <dd className="mono">{settings.dataDir}</dd>
          <dt>License</dt>
          <dd>Apache-2.0, open source</dd>
        </dl>
      </Card>
    </div>
  );
}
