import { ExternalLink, X } from 'lucide-react';
import { useEffect, useRef } from 'react';
import { ChatContext, type DogMood, type PackView } from '../../../shared/pack';
import { leadChat, useLeadChat } from '../lead-chat';
import '../styles/ask.css';
import { LeadConversation, usePack } from '../views/Pack';
import { isAskKey, isTyping } from '../views/nav-keys';
import { useDialogFocus } from './dialog-focus';
import { Dog } from './Dog';

/** Pages whose own content is the conversation, or that come before it. */
const NO_DRAWER = new Set(['pack', 'setup']);

const isMac = navigator.platform.toLowerCase().includes('mac');
export const ASK_SHORTCUT = isMac ? '⌘K' : 'Ctrl+K';

/**
 * Ask the Lead dog from any page: a slim bar at the bottom of the window that
 * opens a chat drawer. Closed by default, and only ever opened by the person,
 * so every message is their own chat (the same rules as the Pack page).
 */
export function AskScout({
  page,
  selected,
  go,
}: {
  page: string;
  selected?: string | undefined;
  go: (route: string) => void;
}) {
  const { open, draft } = useLeadChat();
  const [pack, reload] = usePack({ settings: open });
  const shown = !NO_DRAWER.has(page);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (isAskKey(e, isMac, isTyping(e.target))) {
        e.preventDefault();
        if (shown) leadChat.toggle();
        else go('pack');
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [shown, go]);

  const lead = pack?.dogs.find((d) => d.role === 'lead');
  if (!shown || !pack || !lead) return null;
  const parsed = ChatContext.safeParse({ page, ...(selected ? { selected } : {}) });
  const context = parsed.success ? parsed.data : undefined;

  if (!open)
    return (
      <div className="ask-dock">
        <button
          type="button"
          className="ask-bar"
          onClick={leadChat.open}
          aria-label={`Ask ${lead.name} (${ASK_SHORTCUT})`}
        >
          <Dog breed={lead.breed} mood={lead.mood} size={30} className="ask-bar-dog" />
          <span className={`grow ellipsis ${draft ? '' : 'muted'}`}>
            {draft || `Ask ${lead.name} about anything here…`}
          </span>
          <span className="kbd">{ASK_SHORTCUT}</span>
        </button>
      </div>
    );

  return <AskDrawer pack={pack} reload={reload} context={context} go={go} />;
}

function AskDrawer({
  pack,
  reload,
  context,
  go,
}: {
  pack: PackView;
  reload: () => void;
  context: ChatContext | undefined;
  go: (route: string) => void;
}) {
  const lead = pack.dogs.find((d) => d.role === 'lead')!;
  const box = useRef<HTMLElement>(null);
  useDialogFocus(box, leadChat.close, () => document.querySelector<HTMLElement>('.ask-bar'));
  return (
    <section
      ref={box}
      className="ask-drawer"
      role="dialog"
      aria-label={`Ask ${lead.name}`}
      tabIndex={-1}
    >
      <header className="ask-head">
        <Dog breed={lead.breed} mood={lead.mood} size={44} className="ask-head-dog" />
        <span className="col grow" style={{ gap: 0 }}>
          <span className="t-h3">{lead.name}</span>
          <span className="t-small muted">
            {context?.selected ? `Knows what you have open here` : `Knows which page you’re on`}
          </span>
        </span>
        <button
          type="button"
          className="btn sm ghost"
          onClick={() => {
            leadChat.close();
            go('pack');
          }}
        >
          <ExternalLink size={14} /> Pack
        </button>
        <button
          type="button"
          className="btn sm ghost"
          aria-label="Close"
          title="Close (Esc)"
          onClick={leadChat.close}
        >
          <X size={16} />
        </button>
      </header>
      <LeadConversation
        pack={pack}
        reload={reload}
        {...(context ? { context } : {})}
        autoFocus
        openSettings={() => {
          leadChat.close();
          go('settings');
        }}
      />
    </section>
  );
}

/**
 * What the Lead dog acts out next to Home's status: relaxed when nothing
 * needs the person, ears up when something does, busy while an AI job runs.
 * The words stay in the status line; the dog only shows it.
 */
export function homeMood(
  pack: Pick<PackView, 'dogs'> | undefined,
  needsYou: boolean,
): { mood: DogMood; says: string } {
  const busy = pack?.dogs.find((d) => WORKING.includes(d.mood));
  if (needsYou) return { mood: 'waiting', says: 'Something needs you' };
  if (busy) return { mood: busy.mood, says: `${busy.name} is on a job` };
  return { mood: 'idle', says: 'All quiet' };
}

const WORKING: DogMood[] = ['thinking', 'sniffing', 'fetching'];
