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
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import type { SetupMode, SetupStepView, SetupView } from '../../../../shared/setup';
import { useLive, vigil } from '../../api';
import { computer } from '../../platform';
import { PreflightSetup } from '../../components/PreflightSetup';
import { Shield } from '../../components/Shield';
import { useToast } from '../../components/Toasts';
import { Button, Card, Chip, Segmented, StatusMark, type MarkState } from '../../components/ui';
import { ApiKeys, cleanError } from './ApiKeys';
import './onboarding.css';
import { onRovingKeyDown, rovingTabIndex } from '../../components/roving';

// Protection comes first and AI is optional: setup can finish without it.
type Stage = 'protection' | 'ai' | 'review';
const STAGES: { id: Stage; label: string }[] = [
  { id: 'protection', label: 'Protection' },
  { id: 'ai', label: 'AI (optional)' },
  { id: 'review', label: 'Review' },
];

/** How often the wizard re-checks while it's on screen. Only during setup. */
const POLL_MS = 4000;

const MODES: { id: SetupMode; icon: ReactNode; title: string; body: string; cost: string }[] = [
  {
    id: 'local',
    icon: <Laptop size={20} />,
    title: `On this ${computer} only`,
    body: `A small model on your ${computer} explains alerts and suggests rules. Nothing leaves your ${computer}, and it works offline.`,
    cost: 'About 1 GB of disk. Uses memory only while it thinks.',
  },
  {
    id: 'cloud',
    icon: <Cloud size={20} />,
    title: 'Cloud AI',
    body: 'Your ChatGPT plan or an API key explains alerts, and your Claude plan can too when you ask. Vigil sends redacted event summaries only.',
    cost: `Lightest on your ${computer}. Uses a small share of your plan.`,
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
 * The setup view, with a background load that never replaces a newer one: a
 * re-check that started before you picked or skipped something is dropped,
 * so the screen can't jump back.
 */
export function useSetupView(): [SetupView | undefined, (v: SetupView) => void, () => void] {
  const [view, set] = useState<SetupView>();
  const version = useRef(0);
  const setView = useCallback((v: SetupView) => {
    version.current++;
    set(v);
  }, []);
  const reload = useCallback(() => {
    const started = version.current;
    void vigil.getSetup().then((v) => {
      if (version.current === started) setView(v);
    });
  }, [setView]);
  return [view, setView, reload];
}

/**
 * Re-check while the window is in front, so a step turns green soon after its
 * command finishes in Terminal. Only while setup is on screen.
 */
export function useSetupPolling(active: boolean, reload: () => void) {
  useEffect(() => {
    if (!active) return;
    reload();
    const tick = () => {
      if (document.hasFocus()) reload();
    };
    const id = setInterval(tick, POLL_MS);
    window.addEventListener('focus', tick);
    return () => {
      clearInterval(id);
      window.removeEventListener('focus', tick);
    };
  }, [active, reload]);
}

export function SetupWizard({ onDone }: { onDone: () => void }) {
  const [view, setView, reload] = useSetupView();
  const [stage, setStage] = useState<Stage>('protection');
  const [choosing, setChoosing] = useState(false);
  const [checking, setChecking] = useState(false);

  const recheck = useCallback(async () => {
    setChecking(true);
    try {
      setView(await vigil.checkSetup());
    } finally {
      setChecking(false);
    }
  }, [setView]);

  useSetupPolling(true, reload);

  if (!view) return null;
  const idx = STAGES.findIndex((s) => s.id === stage);
  const steps = (g: SetupStepView['group']) => view.steps.filter((s) => s.group === g);

  return (
    <div className="setup scroll">
      <div className="drag" />
      <div className="setup-inner">
        <div className="row" style={{ gap: 10 }}>
          <Shield height={26} />
          <span className="t-h2 grow">Set up Vigil at Home</span>
          {/* Opened again from Home or Settings: leave without finishing anything. */}
          {view.finished && (
            <Button kind="ghost" size="sm" icon={<ArrowLeft size={15} />} onClick={onDone}>
              Back to Vigil
            </Button>
          )}
        </div>
        <ol className="setup-stages" aria-label="Setup steps">
          {STAGES.map((s, i) => (
            <li key={s.id} aria-current={s.id === stage ? 'step' : undefined}>
              <button type="button" onClick={() => setStage(s.id)}>
                <span className="num">{i + 1}</span>
                {s.label}
              </button>
            </li>
          ))}
        </ol>

        {!view.supported && (
          <div className="attn fair">
            Vigil can only check these steps on macOS and Linux. The commands are shown so you can
            read them.
          </div>
        )}

        {stage === 'protection' && (
          <StepList
            title="Protection"
            intro={`These run on your ${computer} whichever way the AI runs, and they do the blocking. Paste each command into a terminal; Vigil checks for the result by itself. Nothing is installed until you run it.`}
            steps={steps('protection')}
            setView={setView}
            checking={checking}
            recheck={recheck}
          />
        )}

        {stage === 'ai' && (!view.mode || choosing) && (
          <ChooseMode
            mode={view.mode}
            onPick={async (m) => {
              setView(await vigil.setSetupMode(m));
              setChoosing(false);
            }}
            onSkip={() => {
              setChoosing(false);
              setStage('review');
            }}
          />
        )}

        {stage === 'ai' && view.mode && !choosing && (
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
            <div className="row">
              <Button kind="ghost" onClick={() => setChoosing(true)}>
                Change where the AI runs
              </Button>
            </div>
          </>
        )}

        {stage === 'review' && <Review view={view} onDone={onDone} />}

        {!(stage === 'ai' && (!view.mode || choosing)) && (
          <div className="row spread">
            {idx > 0 ? (
              <Button
                kind="ghost"
                icon={<ArrowLeft size={15} />}
                onClick={() => setStage(STAGES[idx - 1]!.id)}
              >
                Back
              </Button>
            ) : (
              <span />
            )}
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
  onSkip,
}: {
  mode: SetupMode | undefined;
  onPick: (m: SetupMode) => void;
  onSkip: () => void;
}) {
  const [picked, setPicked] = useState<SetupMode | undefined>(mode);
  return (
    <>
      <div className="col" style={{ gap: 6 }}>
        <h1 className="t-title">Add AI? (optional)</h1>
        <span>
          Protection is already set: detection and blocking run on your {computer} with fixed rules
          and never wait for AI. AI only explains alerts and suggests new rules for you to approve.
          You can skip it and add it later in Settings.
        </span>
      </div>
      <div
        className="mode-grid"
        role="radiogroup"
        aria-label="Where the AI runs"
        onKeyDown={onRovingKeyDown}
      >
        {MODES.map((m, i) => (
          <button
            key={m.id}
            type="button"
            role="radio"
            aria-checked={picked === m.id}
            tabIndex={rovingTabIndex(picked === m.id, i, picked !== undefined)}
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
      <div className="row spread">
        <Button kind="ghost" onClick={onSkip}>
          Skip AI for now
        </Button>
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
  const toast = useToast();
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
            onClick={() =>
              vigil.openSettingsPane('terminal').catch(() =>
                toast({
                  text: 'No terminal app found. Open one yourself and paste the commands.',
                }),
              )
            }
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
          {busy
            ? action.id === 'helper-install'
              ? 'Waiting for your password…'
              : 'Checking…'
            : action.label}
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
            toast({ text: 'Copied. Paste it into a terminal.' });
          }}
        >
          Copy
        </Button>
      </div>
    </div>
  );
}

function Review({ view, onDone }: { view: SetupView; onDone: () => void }) {
  // With no AI chosen, the AI steps aren't part of this setup.
  const shown = view.mode ? view.steps : view.steps.filter((s) => s.group !== 'ai');
  const left = shown.filter(
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
          {shown.map((s) => {
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
          {view.mode ? 'No AI is connected yet.' : 'No AI chosen.'} Protection works without it;
          alerts just won’t have an explanation until you add one in Settings.
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
