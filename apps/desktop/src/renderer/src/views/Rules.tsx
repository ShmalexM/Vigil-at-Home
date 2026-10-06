import type { RuleMode } from '@vigil/core';
import { Pencil, Plus } from 'lucide-react';
import { useState } from 'react';
import type { RuleView } from '../../../shared/ipc';
import { useLive, vigil } from '../api';
import { HoldButton } from '../components/HoldButton';
import { NewRulePanel, RuleEditorPanel } from '../components/RuleEditor';
import { RuleSuggestions } from '../components/RuleSuggestions';
import { useToast } from '../components/Toasts';
import { helperNote, PASSWORD_CANCELLED } from '../format';
import { Button, Card, Chip, Segmented, SeverityMark } from '../components/ui';
import { confirmsFirst, isToolRule, modeLabel, modesFor } from '../rule-modes';
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
  const [creating, setCreating] = useState(false);
  const open = (id: string | undefined) => go?.(id ? `rules/${id}` : 'rules');
  const list = (rules ?? []).filter((r) => filter === 'all' || r.rule.mode === 'shadow');

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
      {creating && (
        <Card>
          <NewRulePanel onClose={() => setCreating(false)} />
        </Card>
      )}
      {list.length === 0 ? (
        <div className="empty">
          <span className="t-h3">No rules yet</span>
          <span className="t-small">
            Detection rules will appear here once the rule packs are installed.
          </span>
        </div>
      ) : (
        <div className="col" style={{ gap: 10 }}>
          {list.map((r) => (
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

  return (
    <Card tight>
      <div className="row rule-row">
        <div className="col grow" style={{ gap: 2 }}>
          <div className="row">
            <span className="t-h3 ellipsis">{rule.name}</span>
            {rule.origin === 'ai' && <Chip tone="ai">AI-drafted</Chip>}
            {rule.origin === 'user' && <Chip>Yours</Chip>}
          </div>
          <span className="t-small clamp-2" title={rule.description}>
            {rule.description}
          </span>
        </div>
        <SeverityMark severity={rule.severity} />
        <Chip title="How often this rule is expected to be right">{rule.fidelity} fidelity</Chip>
        <span
          className="t-small nowrap"
          style={{ width: 104, textAlign: 'right' }}
          title="Matches in the last 14 days, in any mode"
        >
          {matches} in 14 days
        </span>
        <Segmented
          label={`Mode for ${rule.name}`}
          value={rule.mode}
          options={modesFor(rule)}
          onChange={(m) => void set(m)}
        />
        <Button
          size="sm"
          kind={editing ? 'secondary' : 'ghost'}
          icon={<Pencil size={13} />}
          aria-expanded={editing}
          title={`Edit ${rule.name} and its exclusions`}
          onClick={() => onEdit(!editing)}
        >
          {editing ? 'Close' : 'Edit'}
        </Button>
      </div>
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
