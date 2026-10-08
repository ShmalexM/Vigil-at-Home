import type { RuleMode } from '@vigil/core';
import { BellRing, ChevronDown, ChevronRight, Pencil, Plus, Search } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import type { RuleView } from '../../../shared/ipc';
import { useLive, vigil } from '../api';
import { HoldButton } from '../components/HoldButton';
import { NewRulePanel, RuleEditorPanel } from '../components/RuleEditor';
import { RuleSuggestions } from '../components/RuleSuggestions';
import { useToast } from '../components/Toasts';
import { helperNote, PASSWORD_CANCELLED } from '../format';
import { Button, Card, Chip, Segmented, SeverityMark } from '../components/ui';
import {
  confirmsFirst,
  INTERRUPT_TEXT,
  interruptLevel,
  isToolRule,
  modeLabel,
  modesFor,
  RAISED_BY_VIGIL,
  visibleRules,
  type RuleSort,
} from '../rule-modes';
import '../styles/rules.css';
import { PageHead } from './AppShell';

export function RulesView({
  selected,
  go,
}: {
  selected?: string | undefined;
  go?: (route: string) => void;
}) {
  const [rules] = useLive(() => vigil.listRules());
  const [filter, setFilter] = useState<'all' | 'review'>('all');
  const [text, setText] = useState('');
  const [sort, setSort] = useState<RuleSort>('default');
  const [creating, setCreating] = useState(false);
  const open = (id: string | undefined) => go?.(id ? `rules/${id}` : 'rules');
  const all = rules ?? [];
  const list = visibleRules(all, { text, filter, sort });
  // A rule opened by link (from an alert) stays in the list and scrolls into view.
  const shown =
    selected && !list.some((r) => r.rule.id === selected)
      ? all.find((r) => r.rule.id === selected)
      : undefined;
  const rows = shown ? [shown, ...list] : list;

  return (
    <div className="page">
      <PageHead
        title="Rules"
        purpose="Rules decide instantly and offline; the AI never blocks on its own. Rules you write start in Shadow, where they only log matches. Suggested changes, from the AI or from your answers, wait until you accept them. Only you move a rule up or down."
        right={
          <>
            <Segmented
              label="Filter"
              value={filter}
              onChange={setFilter}
              options={[
                { value: 'all', label: 'All' },
                { value: 'review', label: 'In shadow' },
              ]}
            />
            <Button size="sm" icon={<Plus size={14} />} onClick={() => setCreating(true)}>
              New rule
            </Button>
          </>
        }
      />
      <RuleSuggestions />
      {all.length > 0 && (
        <div className="row feed-controls">
          <label className="search grow">
            <Search size={14} />
            <input
              type="search"
              placeholder="Search rules by name, description or id"
              aria-label="Search rules"
              value={text}
              onChange={(e) => setText(e.target.value)}
            />
          </label>
          <Segmented
            label="Sort rules"
            value={sort}
            onChange={setSort}
            options={[
              { value: 'default', label: 'Default order' },
              { value: 'matches', label: 'Most matches' },
            ]}
          />
          <span className="t-small nowrap" aria-live="polite">
            {list.length === all.length ? `${all.length} rules` : `${list.length} of ${all.length}`}
          </span>
        </div>
      )}
      {creating && (
        <Card>
          <NewRulePanel onClose={() => setCreating(false)} />
        </Card>
      )}
      {rows.length === 0 ? (
        all.length === 0 ? (
          <div className="empty">
            <span className="t-h3">No rules yet</span>
            <span className="t-small">
              Detection rules will appear here once the rule packs are installed.
            </span>
          </div>
        ) : (
          <div className="empty">
            <span className="t-h3">No rules match</span>
            <span className="t-small">
              {filter === 'review' && !text.trim()
                ? 'No rule is in Shadow right now. Rules you write or accept start there.'
                : 'Try other words, or show all rules.'}
            </span>
            <Button
              size="sm"
              kind="ghost"
              onClick={() => {
                setText('');
                setFilter('all');
              }}
            >
              Show all rules
            </Button>
          </div>
        )
      ) : (
        <div className="col" style={{ gap: 10 }}>
          {rows.map((r) => (
            <RuleRow
              key={r.rule.id}
              view={r}
              editing={selected === r.rule.id}
              onEdit={(on) => open(on ? r.rule.id : undefined)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

/** What the modes mean, beside the control. */
const MODE_HELP = {
  rule: 'Shadow only logs matches. Alert tells you. Block also acts at once.',
  tool: 'Record only logs the step. Ask has Claude Code ask you. Deny stops it.',
  raised: 'Record only logs it. Alert tells you.',
};

function RuleRow({
  view,
  editing,
  onEdit,
}: {
  view: RuleView;
  editing: boolean;
  onEdit: (on: boolean) => void;
}) {
  const { rule, matches } = view;
  const toast = useToast();
  const [confirmBlock, setConfirmBlock] = useState(false);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (editing) ref.current?.scrollIntoView({ block: 'start', behavior: 'smooth' });
  }, [editing]);
  const interrupts = interruptLevel(rule);
  // A tool rule answers Claude Code's hook: its modes are Record, Ask and Deny.
  const tool = isToolRule(rule);

  const set = async (mode: RuleMode) => {
    // Picking anything else dismisses a Block confirmation still showing.
    const confirm = confirmsFirst(rule.mode, mode);
    setConfirmBlock(confirm);
    if (confirm) return;
    const before = rule.mode;
    const { helper } = await vigil.setRuleMode(rule.id, mode);
    if (helper === 'declined') {
      toast({ text: `${rule.name}: ${PASSWORD_CANCELLED}` });
      return;
    }
    toast({
      text: `${rule.name}: ${modeLabel(rule, mode)}.${helperNote(helper)}`,
      undo: () => void vigil.setRuleMode(rule.id, before),
    });
  };

  const expanded = open || editing;
  const tone = rule.mode === 'block' ? 'poor' : rule.mode === 'alert' ? 'fair' : undefined;

  return (
    <Card tight>
      {/* The mode is changed only from the opened row, so a stray click on the list changes nothing. */}
      <button
        ref={ref}
        type="button"
        className="row rule-row rule-head"
        aria-expanded={expanded}
        onClick={() => (editing ? onEdit(false) : setOpen(!open))}
      >
        <div className="col grow" style={{ gap: 2, minWidth: 0 }}>
          <div className="row">
            <span className="t-h3 ellipsis">{rule.name}</span>
            {rule.origin === 'ai' && <Chip tone="ai">AI-drafted</Chip>}
            {rule.origin === 'user' && <Chip>Yours</Chip>}
            {!tool && interrupts === 'popup' && (
              <span className="rule-interrupts" title={INTERRUPT_TEXT.popup.long}>
                <BellRing size={12} aria-hidden /> {INTERRUPT_TEXT.popup.short}
              </span>
            )}
          </div>
          <span className={`t-small ${expanded ? '' : 'clamp-2'}`} title={rule.description}>
            {rule.description}
          </span>
        </div>
        <span className="row rule-meta">
          <SeverityMark severity={rule.severity} />
          <Chip title="How often this rule is expected to be right">{rule.fidelity} fidelity</Chip>
          <span
            className="t-small nowrap"
            style={{ width: 104, textAlign: 'right' }}
            title="Matches in the last 14 days, in any mode"
          >
            {matches} in 14 days
          </span>
          <Chip
            tone={tone}
            title="What this rule does when it matches. Open the rule to change it."
          >
            {modeLabel(rule, rule.mode)}
          </Chip>
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </span>
      </button>
      {expanded && (
        <div className="row rule-controls">
          <span className="t-label">Mode</span>
          <Segmented
            label={`Mode for ${rule.name}`}
            value={rule.mode}
            options={modesFor(rule)}
            onChange={(m) => void set(m)}
          />
          <span className="t-small grow">
            {MODE_HELP[RAISED_BY_VIGIL.has(rule.id) ? 'raised' : tool ? 'tool' : 'rule']}
          </span>
          <Button
            size="sm"
            kind={editing ? 'secondary' : 'ghost'}
            icon={<Pencil size={13} />}
            aria-expanded={editing}
            title={`Edit ${rule.name} and its exclusions`}
            onClick={() => onEdit(!editing)}
          >
            {editing ? 'Close editor' : 'Edit rule'}
          </Button>
        </div>
      )}
      {rule.provenance && (
        <span className="t-small">Why the AI drafted it: {rule.provenance.rationale}</span>
      )}
      {confirmBlock && rule.mode !== 'block' && (
        <div className="attn poor">
          {tool ? (
            <span className="grow">
              In Deny mode Claude Code stops every step this rule matches, without asking you.
            </span>
          ) : (
            <span className="grow">
              In Block mode this rule acts on its own: {rule.response.length || 'no'} response
              action
              {rule.response.length === 1 ? '' : 's'} run the moment it matches.
            </span>
          )}
          <button type="button" className="btn sm ghost" onClick={() => setConfirmBlock(false)}>
            Cancel
          </button>
          <HoldButton
            size="sm"
            label={tool ? 'Hold to turn on Deny' : 'Hold to turn on blocking'}
            doneLabel={tool ? 'Denying' : 'Blocking'}
            onConfirm={async () => {
              const { helper } = await vigil.setRuleMode(rule.id, 'block');
              setConfirmBlock(false);
              if (helper === 'unavailable')
                toast({ text: `${rule.name}: ${modeLabel(rule, 'block')}.${helperNote(helper)}` });
            }}
          />
        </div>
      )}
      {editing && <RuleEditorPanel id={rule.id} onClose={() => onEdit(false)} />}
    </Card>
  );
}
