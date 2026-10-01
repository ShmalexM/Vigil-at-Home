import {
  ArrowLeft,
  ArrowRight,
  Cloud,
  Copy,
  ExternalLink,
  Laptop,
  Layers,
  RefreshCw,
  SquareTerminal,
} from 'lucide-react';
import { useCallback, useEffect, useState, type ReactNode } from 'react';
import type { SetupMode, SetupStepView, SetupView } from '../../../../shared/setup';
import { useLive, vigil } from '../../api';
import { PreflightSetup } from '../../components/PreflightSetup';
import { Shield } from '../../components/Shield';
import { useToast } from '../../components/Toasts';
import { Button, Card, Chip, Segmented, StatusMark, type MarkState } from '../../components/ui';
import { ApiKeys, cleanError } from './ApiKeys';
import './onboarding.css';

type Stage = 'choose' | 'protection' | 'ai' | 'review';
const STAGES: { id: Stage; label: string }[] = [
  { id: 'choose', label: 'How Vigil runs' },
  { id: 'protection', label: 'Protection' },
  { id: 'ai', label: 'AI' },
  { id: 'review', label: 'Review' },
];

/** How often the wizard re-checks while it's on screen. Only during setup. */
const POLL_MS = 4000;

const MODES: { id: SetupMode; icon: ReactNode; title: string; body: string; cost: string }[] = [
  {
    id: 'local',
    icon: <Laptop size={20} />,
    title: 'On this Mac only',
    body: 'A small model on your Mac explains alerts and suggests rules. Nothing leaves your Mac, and it works offline.',
    cost: 'About 1 GB of disk. Uses memory only while it thinks.',
  },
  {
    id: 'cloud',
    icon: <Cloud size={20} />,
    title: 'Cloud AI',
    body: 'Your ChatGPT plan or an API key explains alerts, and your Claude plan can too when you ask. Vigil sends redacted event summaries only.',
    cost: 'Lightest on your Mac. Uses a small share of your plan.',
  },
  {
    id: 'both',
    icon: <Layers size={20} />,
    title: 'Both',
    body: 'Routine work runs on the local model; harder questions go to your cloud AI, and it falls back to local when the cloud is out of reach.',
    cost: 'About 1 GB of disk plus a small share of your plan.',
  },
];

/**
 * Re-check while the window is in front, so a step turns green soon after its
 * command finishes in Terminal. Only while setup is on screen.
 */
export function useSetupPolling(active: boolean, setView: (v: SetupView) => void) {
  useEffect(() => {
    if (!active) return;
    const tick = () => {
      if (document.hasFocus()) void vigil.getSetup().then(setView);
    };
    const id = setInterval(tick, POLL_MS);
    window.addEventListener('focus', tick);
    return () => {
      clearInterval(id);
      window.removeEventListener('focus', tick);
    };
  }, [active, setView]);
}

export function SetupWizard({ onDone }: { onDone: () => void }) {
  const [view, setView] = useState<SetupView>();
  const [stage, setStage] = useState<Stage>('choose');
  const [checking, setChecking] = useState(false);

  const recheck = useCallback(async () => {
    setChecking(true);
    try {
      setView(await vigil.checkSetup());
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    void vigil.getSetup().then((v) => {
      setView(v);
      if (v.mode) setStage('protection');
    });
  }, []);

  useSetupPolling(stage !== 'choose', setView);

  if (!view) return null;
  const idx = STAGES.findIndex((s) => s.id === stage);
  const steps = (g: SetupStepView['group']) => view.steps.filter((s) => s.group === g);

  return (
    <div className="setup scroll">
      <div className="drag" />
      <div className="setup-inner">
        <div className="row" style={{ gap: 10 }}>
          <Shield height={26} />
          <span className="t-h2">Set up Vigil at Home</span>
        </div>
        <ol className="setup-stages" aria-label="Setup steps">
          {STAGES.map((s, i) => (
            <li key={s.id} aria-current={s.id === stage ? 'step' : undefined}>
              <button type="button" disabled={i > 0 && !view.mode} onClick={() => setStage(s.id)}>
                <span className="num">{i + 1}</span>
                {s.label}
              </button>
            </li>
          ))}
        </ol>

        {!view.supported && stage !== 'choose' && (
          <div className="attn fair">
            Vigil can only check these steps on macOS. The commands are shown so you can read them.
          </div>
        )}

        {stage === 'choose' && (
          <ChooseMode
            mode={view.mode}
            onPick={async (m) => {
              setView(await vigil.setSetupMode(m));
              setStage('protection');
            }}
          />
        )}

        {stage === 'protection' && (
          <StepList
            title="Protection"
            intro="These run on your Mac whichever way the AI runs, and they do the blocking. Paste each command into Terminal; Vigil checks for the result by itself. Nothing is installed until you run it."
            steps={steps('protection')}
            setView={setView}
            checking={checking}
            recheck={recheck}
          />
        )}

        {stage === 'ai' && (
          <>
            <StepList
              title="AI"
              intro={
                view.mode === 'local'
                  ? 'The local model explains alerts and suggests rules. It never decides a block: blocking runs on fixed rules and never waits for AI.'
                  : 'Vigil uses whichever of these you have, in this order. Protection works without any of them: the AI explains alerts and suggests rules, and never decides a block.'
              }
              steps={steps('ai')}
              setView={setView}
              checking={checking}
              recheck={recheck}
            />
            {view.mode !== 'local' && <ApiKeys view={view} setView={setView} />}
          </>
        )}

        {stage === 'review' && <Review view={view} onDone={onDone} />}

        {stage !== 'choose' && (
          <div className="row spread">
            <Button
              kind="ghost"
              icon={<ArrowLeft size={15} />}
              onClick={() => setStage(STAGES[idx - 1]!.id)}
            >
              Back
            </Button>
            {stage !== 'review' && (
              <Button kind="primary" onClick={() => setStage(STAGES[idx + 1]!.id)}>
                Next
                <ArrowRight size={15} />
              </Button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function ChooseMode({
  mode,
  onPick,
}: {
  mode: SetupMode | undefined;
  onPick: (m: SetupMode) => void;
}) {
  const [picked, setPicked] = useState<SetupMode | undefined>(mode);
  return (
    <>
      <div className="col" style={{ gap: 6 }}>
        <h1 className="t-title">Where should Vigil’s AI run?</h1>
        <span>
          Detection and blocking always run on your Mac with fixed rules, so they are instant and
          never wait for AI. The AI explains alerts and suggests new rules for you to approve. You
          can change this later in Settings.
        </span>
      </div>
      <div className="mode-grid" role="radiogroup" aria-label="Where the AI runs">
        {MODES.map((m) => (
          <button
            key={m.id}
            type="button"
            role="radio"
            aria-checked={picked === m.id}
            className="mode-card"
            onClick={() => setPicked(m.id)}
          >
            <span className="mode-icon">{m.icon}</span>
            <span className="t-h2">{m.title}</span>
            <span>{m.body}</span>
            <span className="t-small">{m.cost}</span>
          </button>
        ))}
      </div>
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <Button kind="primary" disabled={!picked} onClick={() => picked && onPick(picked)}>
          Continue
          <ArrowRight size={15} />
        </Button>
      </div>
    </>
  );
}

function StepList({
  title,
  intro,
  steps,
  setView,
  checking,
  recheck,
}: {
  title: string;
  intro: string;
  steps: SetupStepView[];
  setView: (v: SetupView) => void;
  checking: boolean;
  recheck: () => void;
}) {
  const required = steps.filter((s) => !s.optional);
  const done = required.filter((s) => s.state === 'done').length;
  return (
    <>
      <div className="row spread page-head">
        <div className="col" style={{ gap: 5 }}>
          <h1 className="t-title">{title}</h1>
          <span style={{ maxWidth: 640 }}>{intro}</span>
        </div>
        <div className="row">
          {required.length > 0 && (
            <span className="t-label nowrap">
              {done} of {required.length} done
            </span>
          )}
          <Button
            icon={<SquareTerminal size={15} />}
            onClick={() => void vigil.openSettingsPane('terminal')}
          >
            Open Terminal
          </Button>
          <Button
            icon={<RefreshCw size={15} className={checking ? 'spin' : ''} />}
            onClick={recheck}
          >
            Check again
          </Button>
        </div>
      </div>
      {steps.map((s) => (
        <StepCard key={s.id} step={s} setView={setView} />
      ))}
    </>
  );
}

function StepAction({
  action,
  setView,
}: {
  action: NonNullable<SetupStepView['action']>;
  setView: (v: SetupView) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  return (
    <div className="col" style={{ gap: 6 }}>
      <div className="row">
        <Button
          kind="primary"
          size="sm"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setError(undefined);
            try {
              setView(await vigil.runSetupAction(action.id));
            } catch (err) {
              setError(cleanError(err));
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? 'Checking…' : action.label}
        </Button>
      </div>
      {error && (
        <span className="t-small" role="alert" style={{ color: 'var(--poor)' }}>
          {error}
        </span>
      )}
    </div>
  );
}

const MARK: Record<SetupStepView['state'], [MarkState, string]> = {
  done: ['done', 'Done'],
  todo: ['pending', 'To do'],
  waiting: ['pending', 'Waiting on an earlier step'],
  unavailable: ['warn', 'Not available yet'],
};

export function StepCard({
  step,
  setView,
}: {
  step: SetupStepView;
  setView: (v: SetupView) => void;
}) {
  const [mark, markLabel] = MARK[step.state];
  const open = step.state === 'todo' && !step.skipped;
  return (
    <Card tight className={`step-card ${step.state} ${step.skipped ? 'skipped' : ''}`}>
      <div className="row spread" style={{ alignItems: 'flex-start' }}>
        <div className="row" style={{ alignItems: 'flex-start', gap: 10 }}>
          <StatusMark state={mark} label={markLabel} />
          <div className="col" style={{ gap: 3 }}>
            <div className="row" style={{ gap: 8 }}>
              <h2 className="t-h3">{step.title}</h2>
              {step.optional && <Chip>Optional</Chip>}
              {step.skipped && <Chip tone="fair">Skipped</Chip>}
              {step.state === 'waiting' && <Chip>Do the steps above first</Chip>}
            </div>
            <span className="t-small">{step.why}</span>
            {step.detail && (
              <span className={`t-small step-detail ${step.state}`}>{step.detail}</span>
            )}
          </div>
        </div>
        {step.state !== 'done' && step.state !== 'unavailable' && (
          <Button
            kind="ghost"
            size="sm"
            onClick={async () => setView(await vigil.skipSetupStep(step.id, !step.skipped))}
          >
            {step.skipped ? 'Undo skip' : 'Skip'}
          </Button>
        )}
      </div>
      {step.id === 'claude' && <ClaudePlanSwitch />}
      {step.id === 'claude-preflight' && !step.skipped && (
        <div className="step-plan">
          <PreflightSetup compact />
        </div>
      )}
      {open && (
        <div className="col step-body">
          {step.action && <StepAction action={step.action} setView={setView} />}
          {step.commands.map((c) => (
            <Command key={c.cmd} label={c.label} cmd={c.cmd} />
          ))}
          {step.manual.map((m) => (
            <div key={m.text} className="row spread manual">
              <span>{m.text}</span>
              {m.pane && (
                <Button
                  size="sm"
                  icon={<ExternalLink size={14} />}
                  onClick={() => void vigil.openSettingsPane(m.pane!)}
                >
                  Open System Settings
                </Button>
              )}
            </div>
          ))}
          <span className="t-small">Vigil checks: {step.checks}</span>
        </div>
      )}
    </Card>
  );
}

/**
 * The Claude plan is opt-in and off by default. When on, it's used only when
 * the user asks Vigil to explain an alert.
 */
function ClaudePlanSwitch() {
  const [plan, reload] = useLive(async () => (await vigil.getAiPrefs()).claudePlan);
  return (
    <div className="row spread step-plan">
      <span className="t-small">
        Use my Claude plan, only when I ask Vigil to explain an alert.
      </span>
      <Segmented
        label="Use my Claude plan"
        value={plan ? 'on' : 'off'}
        options={[
          { value: 'off', label: 'Off' },
          { value: 'on', label: 'On' },
        ]}
        onChange={async (v) => {
          await vigil.setAiPrefs({ claudePlan: v === 'on' });
          reload();
        }}
      />
    </div>
  );
}

function Command({ label, cmd }: { label: string; cmd: string }) {
  const toast = useToast();
  return (
    <div className="col" style={{ gap: 4 }}>
      <span className="t-label">{label}</span>
      <div className="command">
        <code className="mono">{cmd}</code>
        <Button
          size="sm"
          kind="ghost"
          icon={<Copy size={14} />}
          aria-label={`Copy: ${label}`}
          onClick={async () => {
            await navigator.clipboard.writeText(cmd);
            toast({ text: 'Copied. Paste it into Terminal.' });
          }}
        >
          Copy
        </Button>
      </div>
    </div>
  );
}

function Review({ view, onDone }: { view: SetupView; onDone: () => void }) {
  const left = view.steps.filter(
    (s) => !s.optional && !s.skipped && (s.state === 'todo' || s.state === 'waiting'),
  );
  const aiReady =
    view.mode === 'local'
      ? view.steps.some((s) => s.id === 'ollama-model' && s.state === 'done')
      : view.steps.some((s) => s.group === 'ai' && s.state === 'done') ||
        view.keys.some((k) => k.saved);
  const pending = view.steps.filter((s) => s.state === 'unavailable');
  return (
    <>
      <div className="col" style={{ gap: 6 }}>
        <h1 className="t-title">{left.length ? 'Almost there' : 'You’re set up'}</h1>
        <span>
          {left.length
            ? 'You can finish now and come back to the rest from Settings › Run setup again. Vigil shows Fair until protection is complete.'
            : 'Vigil is watching. It lives in the menu bar and will pop up only when it blocks something or needs you.'}
        </span>
      </div>
      <Card>
        <ul className="review-list">
          {view.steps.map((s) => {
            const [mark, label] = MARK[s.state];
            return (
              <li key={s.id} className="row" style={{ gap: 10 }}>
                <StatusMark
                  state={s.skipped ? 'warn' : mark}
                  label={s.skipped ? 'Skipped' : label}
                />
                <span className="grow">{s.title}</span>
                <span className="t-small">
                  {s.skipped
                    ? 'Skipped'
                    : s.state === 'done'
                      ? (s.detail ?? 'Done')
                      : s.optional
                        ? 'Not set up (optional)'
                        : label}
                </span>
              </li>
            );
          })}
        </ul>
      </Card>
      {!aiReady && (
        <div className="attn fair">
          No AI is connected yet. Protection still works; alerts just won’t have an explanation
          until you add one.
        </div>
      )}
      {pending.length > 0 && view.supported && (
        <div className="attn accent">
          {pending.map((s) => s.title).join(' and ')} {pending.length === 1 ? 'isn’t' : 'aren’t'}{' '}
          set up yet. Until then blocks are simulated and labelled that way.
        </div>
      )}
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <Button
          kind="primary"
          size="lg"
          onClick={async () => {
            await vigil.finishSetup();
            onDone();
          }}
        >
          {left.length ? 'Finish for now' : 'Finish'}
        </Button>
      </div>
    </>
  );
}
