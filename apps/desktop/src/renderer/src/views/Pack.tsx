import {
  ArrowUp,
  Bone,
  BookOpen,
  Brain,
  Check,
  Dice5,
  Hand,
  Moon,
  Pencil,
  Play,
  Plug,
  Plus,
  RefreshCw,
  Sparkles,
  Sun,
  Trash2,
  X,
  Zap,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState, type ReactNode, type RefObject } from 'react';
import type {
  Breed,
  ChatContext,
  ChatMessage,
  ConnectorView,
  DogMood,
  LeadAction,
  PackView,
  PermissionMode,
  Schedule,
  ToolChoice,
  ToolView,
} from '../../../shared/pack';
import { nextRunAt, nextRunWords } from '../../../shared/pack';
import { vigil } from '../api';
import { useDialogFocus } from '../components/dialog-focus';
import { HoldButton } from '../components/HoldButton';
import { ApprovalStack } from '../components/ApprovalStack';
import { NotebookSheet } from '../components/Notebook';
import { StreamingText } from '../components/StreamingText';
import { Thinking } from '../components/Thinking';
import { MemoryChangeCard, MemorySheet } from '../components/PackMemory';
import { onRovingKeyDown, rovingKeyDown, rovingTabIndex } from '../components/roving';
import { BREEDS, Dog, breedName } from '../components/Dog';
import { useToast } from '../components/Toasts';
import { STARTERS, contextStarter, leadChat, useLeadChat } from '../lead-chat';
import { Button, Card, Chip, Segmented } from '../components/ui';
import { timeAgo } from '../format';
import '../styles/dog.css';
import '../styles/pack.css';
import { PageHead } from './AppShell';

type PackDog = PackView['dogs'][number];

/**
 * The pack, reloaded whenever main says it changed. Pass `settings: false`
 * where only the dogs matter (the bar on every page), to skip reloading on
 * every alert and settings change.
 */
export function usePack({ settings = true }: { settings?: boolean } = {}): [
  PackView | undefined,
  () => void,
] {
  const [pack, setPack] = useState<PackView>();
  const reload = useRef(() => {
    vigil.getPack().then(setPack, (err: unknown) => console.error(err));
  }).current;
  useEffect(() => {
    reload();
    const a = vigil.on('pack', reload);
    const b = settings ? vigil.on('changed', reload) : undefined;
    return () => {
      a();
      b?.();
    };
  }, [reload, settings]);
  return [pack, reload];
}

/**
 * Arrows only move focus between the modes; Space, Enter or a click picks one.
 * Picking saves at once, so one arrow press must never land on Full access,
 * and the arrows stop at the ends instead of wrapping round to it.
 */
const onModeKeyDown = rovingKeyDown({ select: false, wrap: false });

const MODES: { id: PermissionMode; label: string; icon: ReactNode; says: string }[] = [
  {
    id: 'ask',
    label: 'Ask for approval',
    icon: <Hand size={14} />,
    says: 'The Lead dog asks before it changes the pack, and dogs ask before any tool that can change something.',
  },
  {
    id: 'auto',
    label: 'Let AI decide',
    icon: <Sparkles size={14} />,
    says: 'Your AI rates each tool call. Low-risk calls go ahead; anything riskier waits for you.',
  },
  {
    id: 'full',
    label: 'Full access',
    icon: <Zap size={14} />,
    says: 'The pack goes ahead without asking, except where a Vigil rule or your own tool setting says ask.',
  },
];

type Tab = 'pack' | 'tools';

export function PackPage() {
  const [pack, reload] = usePack();
  const [tab, setTab] = useState<Tab>('pack');
  const [editing, setEditing] = useState<PackDog | 'new' | undefined>();
  if (!pack) return <div className="page pack" />;
  const mode = MODES.find((m) => m.id === pack.mode)!;
  const waiting =
    pack.approvals.length +
    pack.chat.reduce(
      (n, m) =>
        n +
        (m.actions?.filter((a) => a.status === 'pending').length ?? 0) +
        (m.memory?.filter((c) => c.status === 'pending').length ?? 0),
      0,
    );

  return (
    <div className="page pack">
      <PageHead
        title="Pack"
        purpose="Vigil’s own AI agents. Talk to your Lead dog: it answers from Vigil’s data and builds the pack for the jobs you describe. No dog can block, allow or change a rule."
      />
      <div className="pack-mode">
        <div
          className="seg pack-mode-seg"
          role="radiogroup"
          aria-label="Permission mode"
          onKeyDown={onModeKeyDown}
        >
          {MODES.map((m, i) => (
            <button
              key={m.id}
              type="button"
              role="radio"
              aria-checked={pack.mode === m.id}
              tabIndex={rovingTabIndex(pack.mode === m.id, i, true)}
              className={`mode-${m.id}`}
              onClick={() => {
                if (m.id !== pack.mode) void vigil.setPackMode(m.id).then(reload);
              }}
            >
              {m.icon}
              {m.label}
            </button>
          ))}
        </div>
        <span className="t-small pack-mode-says">
          {mode.says}
          {pack.mode === 'auto' && <> {pack.judge.detail}.</>} Vigil’s rules apply in every mode.
        </span>
      </div>
      <div className="pack-tabs">
        <div className="tabs" role="tablist" onKeyDown={onRovingKeyDown}>
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'pack'}
            onClick={() => setTab('pack')}
          >
            The pack
            {waiting > 0 && <span className="count hot">{waiting}</span>}
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'tools'}
            onClick={() => setTab('tools')}
          >
            Tools and connectors
          </button>
        </div>
        <label
          className="pack-voice t-small"
          title="Turns off the dog talk in the pack’s status lines and the Lead dog’s replies. The dogs stay."
        >
          <input
            type="checkbox"
            checked={pack.voice === 'plain'}
            onChange={(e) =>
              void vigil.setPackVoice(e.target.checked ? 'plain' : 'pack').then(reload)
            }
          />
          Plain wording
        </label>
      </div>
      {tab === 'pack' ? (
        <div className="pack-layout">
          <LeadPanel
            pack={pack}
            reload={reload}
            onEdit={() => setEditing(pack.dogs.find((d) => d.role === 'lead'))}
          />
          <PackGrid pack={pack} onEdit={setEditing} reload={reload} />
        </div>
      ) : (
        <ToolsTab pack={pack} reload={reload} />
      )}
      {editing && (
        <DogEditor
          dog={editing === 'new' ? undefined : editing}
          tools={pack.tools}
          onClose={() => setEditing(undefined)}
          reload={reload}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------- the Lead dog

export function LeadPanel({
  pack,
  reload,
  onEdit,
}: {
  pack: PackView;
  reload: () => void;
  /** Opens the editor for the Lead dog: a different breed and name. */
  onEdit?: () => void;
}) {
  const lead = pack.dogs.find((d) => d.role === 'lead')!;
  const head = useRef<HTMLDivElement>(null);
  useFitToWindow(head);
  return (
    <Card className="lead-panel">
      <div className="lead-head" ref={head}>
        <Dog breed={lead.breed} mood={lead.mood} size={140} className="lead-dog" />
        <div className="col" style={{ gap: 4, minWidth: 0 }}>
          <span className="row" style={{ gap: 8 }}>
            <NameField dog={lead} reload={reload} />
            <span className="lead-badge">
              <Bone size={12} /> Lead dog
            </span>
          </span>
          <span className="t-small">{breedName(lead.breed)}</span>
          <MoodLine
            dog={lead}
            fallback={pack.noAi ? 'Needs an AI to talk' : 'Ready when you are'}
          />
          <span className="row lead-actions">
            {onEdit && (
              <Button size="sm" kind="ghost" icon={<Pencil size={13} />} onClick={onEdit}>
                Change Lead dog
              </Button>
            )}
            <NotebookButton dog={lead} />
            <MemoryButton count={pack.remembered} />
          </span>
        </div>
      </div>
      <LeadConversation pack={pack} reload={reload} />
    </Card>
  );
}

/**
 * Keeps the Lead panel's bottom inside the window wherever the page is
 * scrolled, so the message box is always on screen and the log scrolls
 * instead. Before the panel sticks it starts lower down, which the CSS
 * max-height alone can't see.
 */
function useFitToWindow(head: RefObject<HTMLElement | null>) {
  useEffect(() => {
    const panel = head.current?.parentElement;
    if (!panel) return;
    const fit = () => {
      const box = panel.getBoundingClientRect();
      // Client pixels to CSS pixels, for the text-size zoom.
      const zoom = panel.offsetHeight ? box.height / panel.offsetHeight : 1;
      const room = (innerHeight - Math.max(box.top, 0) - 16) / zoom;
      // The floor keeps the panel usable before it sticks, but never taller
      // than the window itself, or the message box falls off the bottom when
      // zoomed in.
      const floor = Math.min(320, (innerHeight - 32) / zoom);
      panel.style.maxHeight = `${Math.max(0, Math.floor(Math.max(floor, room)))}px`;
    };
    fit();
    const page = new ResizeObserver(fit);
    page.observe(panel.closest('.page') ?? panel);
    addEventListener('resize', fit);
    addEventListener('scroll', fit, true);
    return () => {
      page.disconnect();
      removeEventListener('resize', fit);
      removeEventListener('scroll', fit, true);
    };
  }, [head]);
}

/**
 * The chat with the Lead dog: its log, any approvals, and the message box.
 * The same conversation shows on the Pack page and in the Ask drawer.
 */
export function LeadConversation({
  pack,
  reload,
  context,
  autoFocus,
  openSettings = () => (location.hash = 'settings'),
}: {
  pack: PackView;
  reload: () => void;
  /** Where the person is, so "what's this?" has an answer. */
  context?: ChatContext;
  autoFocus?: boolean;
  /** Opens Settings; the Ask drawer passes one that also closes itself. */
  openSettings?: () => void;
}) {
  const lead = pack.dogs.find((d) => d.role === 'lead')!;
  const { draft, sending, error } = useLeadChat();
  const log = useRef<HTMLDivElement>(null);
  const names = new Map(pack.dogs.map((d) => [d.id, d]));
  const canSend = !!draft.trim() && !sending && !pack.noAi;
  // Answers that arrive while the chat is open come in word by word; the rest are just there.
  const [openedAt] = useState(Date.now);

  useEffect(() => {
    log.current?.scrollTo({ top: log.current.scrollHeight });
  }, [pack.chat.length, pack.approvals.length, sending]);

  const send = (words: string) =>
    void leadChat.send(words, { noAi: pack.noAi, ...(context ? { context } : {}) }).finally(reload);

  return (
    <>
      <div className="lead-log scroll" ref={log}>
        {pack.chat.length === 0 && (
          <div className="lead-empty col">
            <span className="t-small">
              Ask {lead.name} about this Mac, or describe a job and {lead.name} will find the right
              dog for it.
            </span>
            <div className="row wrap" style={{ gap: 6 }}>
              {[contextStarter(context), ...STARTERS]
                .filter((s): s is string => !!s)
                .map((s) => (
                  <button
                    key={s}
                    type="button"
                    className="starter"
                    disabled={pack.noAi || sending}
                    onClick={() => send(s)}
                  >
                    {s}
                  </button>
                ))}
            </div>
          </div>
        )}
        {pack.chat.map((m) => (
          <Message
            key={m.id}
            m={m}
            fresh={m.at > openedAt}
            plain={pack.voice === 'plain'}
            lead={lead}
            dogs={names}
            tools={pack.tools}
            reload={reload}
          />
        ))}
        {sending && (
          <div className="msg lead">
            <Dog breed={lead.breed} mood="thinking" size={48} className="msg-dog" />
            <Thinking
              working
              active={pack.voice === 'plain' ? 'Working on it' : `${lead.name} is sniffing around`}
              done=""
            />
          </div>
        )}
        <ApprovalStack approvals={pack.approvals} dogs={names} reload={reload} />
      </div>
      {pack.noAi && (
        <span className="t-small no-ai">
          <button type="button" className="link" onClick={() => openSettings()}>
            Set up an AI in Settings
          </button>{' '}
          so {lead.name} can talk.
        </span>
      )}
      {error && (
        <span className="t-small send-error" role="alert">
          {error}
        </span>
      )}
      <form
        className="composer"
        onSubmit={(e) => {
          e.preventDefault();
          if (canSend) send(draft);
        }}
      >
        <textarea
          className="field"
          rows={2}
          value={draft}
          // The drawer opens to type in; the Pack page doesn't steal focus.
          autoFocus={autoFocus}
          aria-label={`Message ${lead.name}`}
          placeholder={`Message ${lead.name}…`}
          onChange={(e) => leadChat.setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
              e.preventDefault();
              if (canSend) send(draft);
            }
          }}
        />
        <button type="submit" className="btn primary send" disabled={!canSend} aria-label="Send">
          <ArrowUp size={16} />
        </button>
      </form>
      <span className="t-small muted lead-foot">
        {pack.leadMayUsePlan
          ? 'Your messages may use your Claude plan. Pack jobs never do.'
          : 'Chats and pack jobs use the AI you set up in Settings.'}
        {pack.chat.length > 0 && (
          <button
            type="button"
            className="link"
            onClick={() => void vigil.clearLeadChat().then(reload)}
          >
            Clear chat
          </button>
        )}
      </span>
    </>
  );
}

function Message({
  m,
  fresh,
  plain,
  lead,
  dogs,
  tools,
  reload,
}: {
  m: ChatMessage;
  fresh: boolean;
  plain: boolean;
  lead: PackDog;
  dogs: Map<string, PackDog>;
  tools: ToolView[];
  reload: () => void;
}) {
  const [revealed, setRevealed] = useState(!fresh);
  const onRevealed = useCallback(() => setRevealed(true), []);
  const used = [...new Set(m.used ?? [])];
  if (m.from === 'you')
    return (
      <div className="msg you">
        <div className="bubble">{m.text}</div>
      </div>
    );
  return (
    <div className="msg lead">
      <Dog
        breed={lead.breed}
        mood={m.failed ? 'error' : 'idle'}
        size={40}
        className="msg-dog still"
      />
      <div className="col" style={{ gap: 6, minWidth: 0, flex: 1 }}>
        {used.length > 0 && (
          <Thinking
            working={false}
            active=""
            done={`${plain ? 'Looked at' : 'Sniffed'} ${used.length === 1 ? '1 thing' : `${used.length} things`}`}
            rows={used.map((t) => ({ primary: toolLabel(t) }))}
          />
        )}
        <div className={`bubble ${m.failed ? 'failed' : ''}`}>
          <StreamingText text={m.text} animate={fresh && !m.failed} onDone={onRevealed} />
        </div>
        {revealed && (
          <>
            {m.actions?.map((a) => (
              <ActionCard key={a.id} a={a} msgId={m.id} dogs={dogs} tools={tools} reload={reload} />
            ))}
            {m.memory?.map((c) => (
              <MemoryChangeCard key={c.id} c={c} msgId={m.id} reload={reload} />
            ))}
            <span className="t-small muted">{timeAgo(m.at)}</span>
          </>
        )}
      </div>
    </div>
  );
}

const ACTION_VERB: Record<LeadAction['kind'], string> = {
  create: 'Add to the pack',
  update: 'Change',
  run: 'Send off on its job',
  retire: 'Retire',
};

function ActionCard({
  a,
  msgId,
  dogs,
  tools,
  reload,
}: {
  a: LeadAction;
  msgId: string;
  dogs: Map<string, PackDog>;
  tools: ToolView[];
  reload: () => void;
}) {
  // Connector tools, listed or not, count as able to change things unless set to Always allow.
  const changes = (key: string) => {
    const t = tools.find((x) => x.key === key);
    return t ? !t.readOnly && t.choice !== 'allow' : !key.startsWith('vigil.');
  };
  const target = a.dogId ? dogs.get(a.dogId) : undefined;
  const breed = (a.dog?.breed ?? target?.breed) as Breed | undefined;
  const name = a.dog?.name ?? target?.name ?? 'a dog';
  const decide = (ok: boolean) => void vigil.decideLeadAction(msgId, a.id, ok).then(reload);
  return (
    <div className={`action-card ${a.status}`}>
      {breed && (
        <Dog
          breed={breed}
          mood={a.status === 'pending' ? 'waiting' : 'idle'}
          size={54}
          className="still"
        />
      )}
      <div className="col grow" style={{ gap: 3, minWidth: 0 }}>
        <span className="t-label">
          {ACTION_VERB[a.kind]}: {name}
          {a.kind === 'create' && breed && <span className="muted"> the {breedName(breed)}</span>}
        </span>
        {a.dog?.job && <span className="t-small clamp-2">{a.dog.job}</span>}
        {(a.dog?.schedule || a.dog?.tools) && (
          <span className="row wrap" style={{ gap: 4 }}>
            {a.dog.schedule && <Chip>{SCHEDULE_LABEL[a.dog.schedule]}</Chip>}
            {a.dog.tools?.map((t) => (
              <Chip key={t} tone={changes(t) ? 'fair' : undefined}>
                {toolLabel(t)}
              </Chip>
            ))}
          </span>
        )}
        {a.note && <span className="t-small muted">{a.note}</span>}
      </div>
      {a.status === 'pending' ? (
        <span className="row" style={{ gap: 6 }}>
          <Button size="sm" kind="ghost" onClick={() => decide(false)}>
            Not now
          </Button>
          <Button size="sm" kind="primary" icon={<Check size={14} />} onClick={() => decide(true)}>
            Approve
          </Button>
        </span>
      ) : (
        <Chip tone={a.status === 'done' ? 'good' : a.status === 'failed' ? 'poor' : undefined}>
          {a.status === 'done' ? 'Done' : a.status === 'failed' ? 'Couldn’t' : 'Declined'}
        </Chip>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- the pack

const SCHEDULE_LABEL: Record<Schedule, string> = {
  manual: 'When asked',
  hourly: 'Every hour',
  daily: 'Every day',
  nightly: 'Every night',
};

const MOOD_TONE: Partial<Record<DogMood, string>> = {
  thinking: 'busy',
  sniffing: 'busy',
  fetching: 'busy',
  waiting: 'ask',
  done: 'good',
  error: 'poor',
};

function MoodLine({ dog, fallback }: { dog: PackDog; fallback: string }) {
  const tone = MOOD_TONE[dog.mood];
  return (
    <span className={`mood-line ${tone ?? ''}`}>
      <span className="mood-dot" />
      {dog.activity ?? fallback}
    </span>
  );
}

function PackGrid({
  pack,
  onEdit,
  reload,
}: {
  pack: PackView;
  onEdit: (d: PackDog | 'new') => void;
  reload: () => void;
}) {
  const helpers = pack.dogs.filter((d) => d.role === 'helper');
  const mine = pack.dogs.filter((d) => d.role === 'pack');
  return (
    <div className="col pack-side" style={{ gap: 14 }}>
      <div className="row spread">
        <h2 className="t-h2">Your pack</h2>
        <Button size="sm" icon={<Plus size={14} />} onClick={() => onEdit('new')}>
          Adopt a dog
        </Button>
      </div>
      <div className="dog-grid">
        {mine.map((d) => (
          <DogCard
            key={d.id}
            dog={d}
            lead={pack.dogs[0]!}
            noAi={pack.noAi}
            onEdit={() => onEdit(d)}
            reload={reload}
          />
        ))}
        {mine.length === 0 && (
          <button type="button" className="dog-card adopt" onClick={() => onEdit('new')}>
            <Dog breed="corgi" mood="sleeping" size={96} />
            <span className="t-small">
              No pack dogs yet. Ask the Lead dog for one, or adopt one yourself.
            </span>
          </button>
        )}
      </div>
      <h2 className="t-h2">Built-in helpers</h2>
      <div className="dog-grid helpers">
        {helpers.map((d) => (
          <DogCard
            key={d.id}
            dog={d}
            lead={pack.dogs[0]!}
            noAi={pack.noAi}
            onEdit={() => onEdit(d)}
            reload={reload}
          />
        ))}
      </div>
    </div>
  );
}

function DogCard({
  dog,
  lead,
  noAi,
  onEdit,
  reload,
}: {
  dog: PackDog;
  lead: PackDog;
  /** Helpers can't do their jobs without an AI, so they don't claim to be on duty. */
  noAi: boolean;
  onEdit: () => void;
  reload: () => void;
}) {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const busy = ['thinking', 'sniffing', 'fetching', 'waiting'].includes(dog.mood);
  // The scheduler's own rule; with no AI set up, a scheduled run can't happen.
  const now = Date.now();
  const next = dog.role === 'pack' && !noAi && !busy ? nextRunAt(dog, now) : undefined;
  const run = async () => {
    const r = await vigil.runDog(dog.id);
    if (!r.ok) toast({ text: r.error ?? 'It couldn’t run' });
    reload();
  };
  return (
    <div className={`dog-card mood-${dog.mood}`}>
      <div className="dog-stage">
        <Dog breed={dog.breed} mood={dog.mood} size={dog.role === 'helper' ? 120 : 140} />
      </div>
      <div className="col" style={{ gap: 2, minWidth: 0 }}>
        <span className="row" style={{ gap: 6 }}>
          <span className="t-h3 ellipsis">{dog.name}</span>
          <span className="t-small muted ellipsis">{breedName(dog.breed)}</span>
        </span>
        <MoodLine
          dog={dog}
          fallback={
            dog.role !== 'helper' ? idleLine(dog) : noAi ? 'Off until an AI is set up' : 'On duty'
          }
        />
      </div>
      <span className="t-small clamp-3 dog-job">{dog.job}</span>
      {dog.role === 'pack' && (
        <span className="row wrap" style={{ gap: 4 }}>
          <Chip>{SCHEDULE_LABEL[dog.schedule]}</Chip>
          <Chip>
            {dog.tools.length} {dog.tools.length === 1 ? 'tool' : 'tools'}
          </Chip>
          {dog.createdBy === 'lead' && <Chip tone="ai">Added by {lead.name}</Chip>}
        </span>
      )}
      {next !== undefined && (
        <span className="t-small muted">
          Next run: {nextRunWords(next, now, dog.schedule === 'nightly')}
        </span>
      )}
      {dog.lastReport && (
        <button type="button" className="report" onClick={() => setOpen(!open)}>
          <span className="t-small">
            <b>{dog.lastReport.ok ? 'Last report' : 'Last run failed'}</b> ·{' '}
            {timeAgo(dog.lastReport.at)}
            {dog.lastReport.findings.length > 0 &&
              ` · ${dog.lastReport.findings.length} to look at`}
          </span>
          <span className={`t-small ${open ? '' : 'clamp-2'}`}>{dog.lastReport.summary}</span>
          {open &&
            dog.lastReport.findings.map((f, i) => (
              <span key={i} className="t-small finding">
                <span className={`sev ${f.severity}`} /> {f.title}
                {f.detail && <span className="muted"> {f.detail}</span>}
              </span>
            ))}
        </button>
      )}
      <div className="row dog-actions">
        {dog.role === 'pack' && (
          <Button
            size="sm"
            icon={<Play size={13} />}
            disabled={busy || !dog.enabled}
            onClick={() => void run()}
          >
            Run now
          </Button>
        )}
        <Button size="sm" kind="ghost" icon={<Pencil size={13} />} onClick={onEdit}>
          {dog.role === 'helper' ? 'Rename' : 'Edit'}
        </Button>
        <NotebookButton dog={dog} />
        {dog.role === 'pack' && (
          <Button
            size="sm"
            kind="ghost"
            icon={dog.enabled ? <Moon size={13} /> : <Sun size={13} />}
            onClick={() => void vigil.updateDog(dog.id, { enabled: !dog.enabled }).then(reload)}
          >
            {dog.enabled ? 'Nap' : 'Wake'}
          </Button>
        )}
      </div>
    </div>
  );
}

/** Opens the dog's notebook: what it was asked and the reasons it gave. */
function NotebookButton({ dog }: { dog: PackDog }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button size="sm" kind="ghost" icon={<BookOpen size={13} />} onClick={() => setOpen(true)}>
        Notebook
      </Button>
      {open && (
        <NotebookSheet
          title={`${dog.name}’s notebook`}
          filter={{ dog: dog.id }}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  );
}

/** Opens what the pack remembers. */
function MemoryButton({ count }: { count: number }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button size="sm" kind="ghost" icon={<Brain size={13} />} onClick={() => setOpen(true)}>
        Memory{count > 0 && <span className="count">{count}</span>}
      </Button>
      {open && <MemorySheet onClose={() => setOpen(false)} />}
    </>
  );
}

function idleLine(dog: PackDog): string {
  if (dog.schedule === 'manual') return 'Waiting for a job';
  return `On watch · ${SCHEDULE_LABEL[dog.schedule].toLowerCase()}`;
}

function NameField({ dog, reload }: { dog: PackDog; reload: () => void }) {
  const [edit, setEdit] = useState(false);
  const [name, setName] = useState(dog.name);
  if (!edit)
    return (
      <button type="button" className="name-btn t-h2" title="Rename" onClick={() => setEdit(true)}>
        {dog.name}
        <Pencil size={12} />
      </button>
    );
  const save = () => {
    setEdit(false);
    if (name.trim() && name.trim() !== dog.name)
      void vigil.updateDog(dog.id, { name: name.trim() }).then(reload);
  };
  return (
    <input
      className="field name-field"
      autoFocus
      maxLength={32}
      value={name}
      onChange={(e) => setName(e.target.value)}
      onBlur={save}
      onKeyDown={(e) => {
        if (e.key === 'Enter') save();
        if (e.key === 'Escape') setEdit(false);
      }}
    />
  );
}

// ---------------------------------------------------------------- adopting and editing

const NAMES: Record<Breed, string[]> = {
  shepherd: ['Ranger', 'Atlas', 'Sarge', 'Bolt'],
  doberman: ['Duke', 'Onyx', 'Blitz', 'Vesper'],
  husky: ['Scout', 'Koda', 'Aurora', 'Nova'],
  golden: ['Sunny', 'Honey', 'Maple', 'Biscuit'],
  beagle: ['Biscuit', 'Clue', 'Sherlock', 'Pepper'],
  corgi: ['Waffles', 'Nugget', 'Loaf', 'Toast'],
  dachshund: ['Noodle', 'Frank', 'Pretzel', 'Ziti'],
  chihuahua: ['Pip', 'Taco', 'Chili', 'Peanut'],
};

function DogEditor({
  dog,
  tools,
  onClose,
  reload,
}: {
  dog?: PackDog | undefined;
  tools: ToolView[];
  onClose: () => void;
  reload: () => void;
}) {
  const toast = useToast();
  const role = dog?.role ?? 'pack';
  const [breed, setBreed] = useState<Breed>(dog?.breed ?? 'beagle');
  const [name, setName] = useState(dog?.name ?? '');
  const [job, setJob] = useState(dog?.role === 'pack' ? dog.job : '');
  const [schedule, setSchedule] = useState<Schedule>(dog?.schedule ?? 'manual');
  const [picked, setPicked] = useState<Set<string>>(
    new Set(dog?.tools ?? tools.filter((t) => t.source === 'vigil').map((t) => t.key)),
  );
  const usable = tools.filter((t) => t.choice !== 'off');

  const suggest = () => {
    const list = NAMES[breed];
    setName(list[Math.floor(Math.random() * list.length)] ?? 'Rex');
  };
  const save = async () => {
    try {
      if (!dog) {
        const r = await vigil.adoptDog({
          name: name.trim(),
          breed,
          job: job.trim(),
          schedule,
          tools: [...picked],
        });
        if (!r.ok) throw new Error(r.error);
      } else if (role === 'pack') {
        await vigil.updateDog(dog.id, {
          name: name.trim(),
          breed,
          job: job.trim(),
          schedule,
          tools: [...picked],
        });
      } else if (role === 'lead') {
        await vigil.updateDog(dog.id, { name: name.trim(), breed, tools: [...picked] });
      } else {
        await vigil.updateDog(dog.id, { name: name.trim(), breed });
      }
      reload();
      onClose();
    } catch (err) {
      toast({ text: err instanceof Error ? err.message : String(err) });
    }
  };
  const valid = name.trim() && (role !== 'pack' || job.trim());
  const box = useRef<HTMLDivElement>(null);
  useDialogFocus(box, onClose);

  return (
    <div className="scrim" onClick={onClose}>
      <div
        ref={box}
        className="sheet dog-editor card"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={dog ? `Edit ${dog.name}` : 'Adopt a dog'}
        tabIndex={-1}
      >
        <div className="row spread">
          <h2 className="t-h2">
            {!dog ? 'Adopt a dog' : role === 'lead' ? 'Change your Lead dog' : `Edit ${dog.name}`}
          </h2>
          <button type="button" className="btn ghost icon-btn" aria-label="Close" onClick={onClose}>
            <X size={16} />
          </button>
        </div>
        <div className="breed-picker">
          {BREEDS.map((b) => (
            <button
              key={b.id}
              type="button"
              className="breed"
              aria-pressed={breed === b.id}
              onClick={() => setBreed(b.id)}
              title={b.blurb}
            >
              <Dog breed={b.id} mood={breed === b.id ? 'done' : 'idle'} size={104} />
              <span className="t-small">{b.name}</span>
            </button>
          ))}
        </div>
        <span className="t-small muted">{BREEDS.find((b) => b.id === breed)?.blurb}</span>
        <label className="col" style={{ gap: 4 }}>
          <span className="t-label">Name</span>
          <span className="row" style={{ gap: 6 }}>
            <input
              className="field grow"
              maxLength={32}
              value={name}
              placeholder="Give your dog a name"
              onChange={(e) => setName(e.target.value)}
            />
            <Button size="sm" kind="ghost" icon={<Dice5 size={14} />} onClick={suggest}>
              Suggest
            </Button>
          </span>
        </label>
        {role === 'pack' && (
          <>
            <label className="col" style={{ gap: 4 }}>
              <span className="t-label">Job</span>
              <textarea
                className="field"
                rows={3}
                maxLength={2000}
                value={job}
                placeholder="What should it do each time it runs? For example: check today’s alerts and tell me which ones need me."
                onChange={(e) => setJob(e.target.value)}
              />
            </label>
            <div className="col" style={{ gap: 4 }}>
              <span className="t-label">When</span>
              <Segmented
                label="Schedule"
                value={schedule}
                onChange={setSchedule}
                options={(Object.keys(SCHEDULE_LABEL) as Schedule[]).map((s) => ({
                  value: s,
                  label: SCHEDULE_LABEL[s],
                }))}
              />
            </div>
          </>
        )}
        {role === 'helper' ? (
          <span className="t-small muted">{dog?.job}</span>
        ) : (
          <div className="col" style={{ gap: 6 }}>
            <span className="t-label">Tools it may use</span>
            <div className="tool-picks scroll">
              {usable.map((t) => (
                <label key={t.key} className="tool-pick">
                  <input
                    type="checkbox"
                    checked={picked.has(t.key)}
                    onChange={(e) => {
                      const next = new Set(picked);
                      if (e.target.checked) next.add(t.key);
                      else next.delete(t.key);
                      setPicked(next);
                    }}
                  />
                  <span className="col grow" style={{ gap: 0, minWidth: 0 }}>
                    <span className="t-small">
                      <b>{t.title}</b> <span className="muted">· {t.sourceName}</span>
                    </span>
                    <span className="t-small muted ellipsis">{t.description}</span>
                  </span>
                  <ToolKind t={t} />
                </label>
              ))}
            </div>
          </div>
        )}
        <div className="row spread">
          {dog?.role === 'pack' ? (
            <HoldButton
              size="sm"
              icon={<Trash2 size={14} />}
              label={`Retire ${dog.name}`}
              doneLabel="Retired"
              onConfirm={() => void vigil.retireDog(dog.id).then(() => (reload(), onClose()))}
            />
          ) : (
            <span />
          )}
          <span className="row" style={{ gap: 8 }}>
            <Button kind="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button kind="primary" disabled={!valid} onClick={() => void save()}>
              {dog ? 'Save' : 'Adopt'}
            </Button>
          </span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- tools and connectors

const CHOICES: { value: ToolChoice; label: string }[] = [
  { value: 'auto', label: 'Follow mode' },
  { value: 'ask', label: 'Always ask' },
  { value: 'allow', label: 'Always allow' },
  { value: 'off', label: 'Off' },
];

function ToolsTab({ pack, reload }: { pack: PackView; reload: () => void }) {
  const vigilTools = pack.tools.filter((t) => t.source === 'vigil');
  return (
    <div className="col" style={{ gap: 16 }}>
      <Card>
        <h2 className="t-h2">How a tool call is decided</h2>
        <ol className="gate-steps">
          <li>
            <b>Off</b> tools are never offered to a dog.
          </li>
          <li>
            <b>Vigil’s rules</b> check every connector call first. A rule that stops it stops it in
            every mode, Full access included; a rule that asks always asks.
          </li>
          <li>
            <b>Your choice</b> for the tool comes next: Always ask, or Always allow.
          </li>
          <li>
            <b>Vigil’s own tools</b> only read, so they go ahead. A connector’s tools count as able
            to change things even when its server says they only read, because Vigil can’t check
            that. Set one to Always allow if you trust it.
          </li>
          <li>
            Anything else follows the <b>permission mode</b> at the top of the page.
          </li>
        </ol>
      </Card>
      <Card>
        <h2 className="t-h2">Vigil’s tools</h2>
        <span className="t-small">Read-only, redacted, and they never show rule contents.</span>
        {vigilTools.map((t) => (
          <ToolRow key={t.key} t={t} reload={reload} />
        ))}
      </Card>
      <Connectors pack={pack} reload={reload} />
    </div>
  );
}

/** Whether a tool only reads. Only Vigil's own tools are trusted to; a server's word is shown, not used. */
function ToolKind({ t }: { t: ToolView }) {
  if (t.readOnly) return <Chip>Reads only</Chip>;
  if (t.serverHint) {
    return (
      <span title="The server says this tool only reads. Vigil can’t check that, so it still follows your permission mode.">
        <Chip tone="fair">Server says it only reads</Chip>
      </span>
    );
  }
  return <Chip tone="fair">Can change things</Chip>;
}

function ToolRow({ t, reload }: { t: ToolView; reload: () => void }) {
  return (
    <div className="tool-row">
      <div className="col grow" style={{ gap: 1, minWidth: 0 }}>
        <span className="row" style={{ gap: 6 }}>
          <span className="t-h3">{t.title}</span>
          <ToolKind t={t} />
        </span>
        <span className="t-small muted clamp-2">{t.description}</span>
      </div>
      <Segmented
        label={`${t.title}: when to ask`}
        value={t.choice}
        options={CHOICES}
        onChange={(c) => void vigil.setPackToolChoice(t.key, c).then(reload)}
      />
    </div>
  );
}

function Connectors({ pack, reload }: { pack: PackView; reload: () => void }) {
  const [adding, setAdding] = useState(false);
  return (
    <Card>
      <div className="row spread">
        <div className="col" style={{ gap: 3 }}>
          <h2 className="t-h2">Connectors</h2>
          <span className="t-small">
            Your own MCP servers, added here in Vigil. Vigil connects to them; the AI never sees
            their tokens.
          </span>
        </div>
        <Button size="sm" icon={<Plug size={14} />} onClick={() => setAdding(!adding)}>
          Add a connector
        </Button>
      </div>
      {adding && <ConnectorForm onDone={() => (setAdding(false), reload())} />}
      {pack.connectors.length === 0 && !adding && (
        <span className="t-small muted">
          None yet. GitHub, Slack, Linear or your own server all work.
        </span>
      )}
      {pack.connectors.map((c) => (
        <ConnectorBlock
          key={c.id}
          c={c}
          tools={pack.tools.filter((t) => t.source === c.id)}
          reload={reload}
        />
      ))}
    </Card>
  );
}

function ConnectorBlock({
  c,
  tools,
  reload,
}: {
  c: ConnectorView;
  tools: ToolView[];
  reload: () => void;
}) {
  const toast = useToast();
  const refresh = async () => {
    const r = await vigil.refreshConnector(c.id);
    if (!r.ok) toast({ text: r.error ?? 'It didn’t answer' });
    reload();
  };
  const state =
    c.state === 'connected'
      ? 'Connected'
      : c.state === 'connecting'
        ? 'Connecting…'
        : c.state === 'error'
          ? (c.error ?? 'Couldn’t connect')
          : c.enabled
            ? 'Connects when a dog needs it'
            : 'Off';
  return (
    <div className="connector">
      <div className="row spread">
        <div className="col" style={{ gap: 1, minWidth: 0 }}>
          <span className="row" style={{ gap: 6 }}>
            <span className="t-h3">{c.name}</span>
            <Chip
              tone={c.state === 'connected' ? 'good' : c.state === 'error' ? 'poor' : undefined}
            >
              {state}
            </Chip>
          </span>
          <span className="t-small muted mono ellipsis">{c.target}</span>
          {c.secrets.length > 0 && (
            <span className="t-small muted">Keychain: {c.secrets.join(', ')}</span>
          )}
        </div>
        <span className="row" style={{ gap: 4 }}>
          <Button
            size="sm"
            kind="ghost"
            icon={<RefreshCw size={13} />}
            disabled={!c.enabled}
            onClick={() => void refresh()}
          >
            List tools
          </Button>
          <Button
            size="sm"
            kind="ghost"
            onClick={() => void vigil.setConnectorEnabled(c.id, !c.enabled).then(reload)}
          >
            {c.enabled ? 'Turn off' : 'Turn on'}
          </Button>
          <HoldButton
            size="sm"
            icon={<Trash2 size={13} />}
            label="Remove"
            doneLabel="Removed"
            onConfirm={() => void vigil.removeConnector(c.id).then(reload)}
          />
        </span>
      </div>
      {tools.map((t) => (
        <ToolRow key={t.key} t={t} reload={reload} />
      ))}
    </div>
  );
}

function ConnectorForm({ onDone }: { onDone: () => void }) {
  const toast = useToast();
  const [kind, setKind] = useState<'stdio' | 'http'>('stdio');
  const [name, setName] = useState('');
  const [command, setCommand] = useState('');
  const [env, setEnv] = useState('');
  const [url, setUrl] = useState('');
  const [token, setToken] = useState('');
  const save = async () => {
    const parts = command.trim().split(/\s+/).filter(Boolean);
    const envs = Object.fromEntries(
      env
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean)
        .map((l) => [l.slice(0, l.indexOf('=')).trim(), l.slice(l.indexOf('=') + 1).trim()]),
    );
    const r = await vigil.addConnector(
      kind === 'stdio'
        ? {
            kind,
            name,
            command: parts[0] ?? '',
            args: parts.slice(1),
            ...(env.trim() ? { env: envs } : {}),
          }
        : { kind, name, url, ...(token ? { token } : {}) },
    );
    if (!r.ok) toast({ text: r.error ?? 'Couldn’t add it' });
    else onDone();
  };
  return (
    <div className="connector-form col">
      <Segmented
        label="Connector kind"
        value={kind}
        onChange={setKind}
        options={[
          { value: 'stdio', label: 'A command on this Mac' },
          { value: 'http', label: 'A URL' },
        ]}
      />
      <input
        className="field"
        placeholder="Name, such as GitHub"
        value={name}
        onChange={(e) => setName(e.target.value)}
      />
      {kind === 'stdio' ? (
        <>
          <input
            className="field mono"
            placeholder="npx -y @modelcontextprotocol/server-github"
            value={command}
            onChange={(e) => setCommand(e.target.value)}
          />
          <textarea
            className="field mono"
            rows={2}
            placeholder={
              'Environment, one per line (kept in the Keychain)\nGITHUB_PERSONAL_ACCESS_TOKEN=…'
            }
            value={env}
            onChange={(e) => setEnv(e.target.value)}
          />
        </>
      ) : (
        <>
          <input
            className="field mono"
            placeholder="https://…/mcp"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <input
            className="field mono"
            type="password"
            placeholder="Bearer token (optional, kept in the Keychain)"
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
        </>
      )}
      <span className="row" style={{ gap: 8, justifyContent: 'flex-end' }}>
        <Button
          kind="primary"
          disabled={!name.trim() || (kind === 'stdio' ? !command.trim() : !url.trim())}
          onClick={() => void save()}
        >
          Add
        </Button>
      </span>
    </div>
  );
}

// ---------------------------------------------------------------- helpers

function toolLabel(key: string): string {
  const [, name = key] = key.split(/\.(.*)/);
  return name.replace(/_/g, ' ');
}
