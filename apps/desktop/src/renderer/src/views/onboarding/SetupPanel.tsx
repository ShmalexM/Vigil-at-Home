import { RefreshCw, SquareTerminal, Wrench } from 'lucide-react';
import { useEffect, useState } from 'react';
import type { SetupMode, SetupView } from '../../../../shared/setup';
import { vigil } from '../../api';
import { Button, Card, SectionHead, Segmented } from '../../components/ui';
import { ApiKeys } from './ApiKeys';
import { StepCard, useSetupPolling } from './SetupWizard';
import './onboarding.css';

/**
 * Setup in Settings: the same steps as the wizard with their live status,
 * where the AI runs, and API keys, without walking through setup again.
 */
export function SetupPanel() {
  const [view, setView] = useState<SetupView>();
  const [checking, setChecking] = useState(false);
  useEffect(() => void vigil.getSetup().then(setView), []);
  useSetupPolling(true, setView);
  if (!view) return null;

  const group = (g: 'protection' | 'ai') => view.steps.filter((s) => s.group === g);
  const summary = (g: 'protection' | 'ai') => {
    const req = group(g).filter((s) => !s.optional);
    return `${req.filter((s) => s.state === 'done').length} of ${req.length} done`;
  };

  return (
    <>
      <Card>
        <SectionHead
          title="Where the AI runs"
          sub="Detection and blocking always run on this Mac. This only changes what explains alerts and suggests rules."
          right={
            <Segmented<SetupMode>
              label="Where the AI runs"
              value={view.mode ?? 'both'}
              onChange={async (m) => setView(await vigil.setSetupMode(m))}
              options={[
                { value: 'local', label: 'This Mac' },
                { value: 'cloud', label: 'Cloud' },
                { value: 'both', label: 'Both' },
              ]}
            />
          }
        />
      </Card>
      <Card>
        <SectionHead
          title="Setup"
          sub="What’s installed and connected, checked live. Paste a command into Terminal and its step turns green by itself."
          right={
            <>
              <Button
                icon={<SquareTerminal size={15} />}
                onClick={() => void vigil.openSettingsPane('terminal')}
              >
                Open Terminal
              </Button>
              <Button
                icon={<RefreshCw size={15} className={checking ? 'spin' : ''} />}
                onClick={async () => {
                  setChecking(true);
                  try {
                    setView(await vigil.checkSetup());
                  } finally {
                    setChecking(false);
                  }
                }}
              >
                Check again
              </Button>
            </>
          }
        />
        <div className="row spread">
          <h3 className="t-h3">Protection</h3>
          <span className="t-label">{summary('protection')}</span>
        </div>
        {group('protection').map((s) => (
          <StepCard key={s.id} step={s} setView={setView} />
        ))}
        <div className="row spread">
          <h3 className="t-h3">AI</h3>
          <span className="t-label">{summary('ai')}</span>
        </div>
        {group('ai').map((s) => (
          <StepCard key={s.id} step={s} setView={setView} />
        ))}
        <div className="row" style={{ justifyContent: 'flex-end' }}>
          <Button
            kind="ghost"
            icon={<Wrench size={15} />}
            onClick={async () => {
              await vigil.restartSetup();
              location.hash = 'setup';
            }}
          >
            Walk through setup again
          </Button>
        </div>
      </Card>
      {view.mode !== 'local' && <ApiKeys view={view} setView={setView} />}
    </>
  );
}
