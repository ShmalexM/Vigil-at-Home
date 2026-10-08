import { useEffect } from 'react';
import { BellRing, ClipboardCopy } from 'lucide-react';
import { useLive, vigil } from '../api';
import { AlertViewSwitch } from '../components/Attention';
import { useToast } from '../components/Toasts';
import { Button, Card, SectionHead } from '../components/ui';
import { aboutText, systemName } from './about';
import { AiSection } from './Ai';
import { AppearanceSection } from './Appearance';
import { UpdatesRow } from './Updates';
import { ADVANCED_NAV, PageHead } from './AppShell';
import { SetupPanel } from './onboarding/SetupPanel';

export function SettingsView({ go }: { go: (r: string) => void }) {
  const [settings, reload] = useLive(() => vigil.getSettings());
  const [status] = useLive(() => vigil.getStatus());
  const toast = useToast();
  // The theme can change from another window too.
  useEffect(() => vigil.on('theme', reload), [reload]);
  if (!settings) return null;

  return (
    <div className="page">
      <PageHead title="Settings" purpose="How Vigil looks and behaves on this computer." />
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
            sub="Show me less keeps Home and the menu bar to what needs your decision, with everything Vigil only noticed in History. Show me more lists those on Home too and counts them on the menu-bar icon. What Vigil blocks is the same either way."
          />
          <div className="row spread">
            <span>How much to show</span>
            <AlertViewSwitch value={status.alertView} />
          </div>
        </Card>
      )}
      <SetupPanel />
      <Card>
        <SectionHead
          title="About"
          right={
            <Button
              size="sm"
              kind="ghost"
              icon={<ClipboardCopy size={14} />}
              onClick={async () => {
                await navigator.clipboard.writeText(aboutText(settings, status));
                toast({ text: 'Copied. Paste it into a bug report.' });
              }}
            >
              Copy for a bug report
            </Button>
          }
        />
        <dl className="kv">
          <dt>Version</dt>
          <dd>
            {settings.version}
            {settings.commit && <span className="mono"> ({settings.commit})</span>}
          </dd>
          <dt>Updates</dt>
          <dd>
            <UpdatesRow />
          </dd>
          <dt>System</dt>
          <dd>{systemName(settings.platform, settings.arch)}</dd>
          <dt>Data folder</dt>
          <dd className="mono">{settings.dataDir}</dd>
          <dt>License</dt>
          <dd>Apache-2.0, open source</dd>
        </dl>
      </Card>
      <details className="settings-advanced">
        <summary className="t-h2">Advanced</summary>
        <span className="t-small">
          The detail behind what Vigil does: every alert, the rules, raw activity, AI providers and
          spending. Nothing here is needed day to day.
        </span>
        <Card>
          <SectionHead
            title="Advanced pages"
            sub="Alerts, Rules, Agents, Pack, Activity and Usage. Also under Advanced in the sidebar."
          />
          <div className="row" style={{ flexWrap: 'wrap' }}>
            {ADVANCED_NAV.map((n) => (
              <Button key={n.id} size="sm" icon={n.icon} onClick={() => go(n.id)}>
                {n.label}
              </Button>
            ))}
          </div>
        </Card>
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
      </details>
    </div>
  );
}
