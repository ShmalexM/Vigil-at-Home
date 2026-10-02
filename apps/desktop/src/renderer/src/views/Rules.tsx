import type { RuleMode } from '@vigil/core';
import { Pencil, Plus } from 'lucide-react';
import { useState } from 'react';
import type { RuleView } from '../../../shared/ipc';
import { useLive, vigil } from '../api';
import { HoldButton } from '../components/HoldButton';
import { NewRulePanel, RuleEditorPanel } from '../components/RuleEditor';
import { RuleSuggestions } from '../components/RuleSuggestions';
import { useToast } from '../components/Toasts';
import { Button, Card, Chip, Segmented, SeverityMark } from '../components/ui';
import '../styles/rules.css';
import { PageHead } from './AppShell';

const MODES: { value: RuleMode; label: string }[] = [
  { value: 'disabled', label: 'Off' },
  { value: 'shadow', label: 'Shadow' },
  { value: 'alert', label: 'Alert' },
  { value: 'block', label: 'Block' },
];

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

  const set = async (mode: RuleMode) => {
    if (mode === 'block' && rule.mode !== 'block') {
      setConfirmBlock(true);
      return;
    }
    const before = rule.mode;
    await vigil.setRuleMode(rule.id, mode);
    toast({ text: `${rule.name}: ${mode}`, undo: () => void vigil.setRuleMode(rule.id, before) });
  };

  return (
    <Card tight>
      <div className="row">
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
          options={MODES}
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
      {confirmBlock && (
        <div className="attn poor">
          <span className="grow">
            In Block mode this rule acts on its own: {rule.response.length || 'no'} response action
            {rule.response.length === 1 ? '' : 's'} run the moment it matches.
          </span>
          <button type="button" className="btn sm ghost" onClick={() => setConfirmBlock(false)}>
            Cancel
          </button>
          <HoldButton
            size="sm"
            label="Hold to turn on blocking"
            doneLabel="Blocking"
            onConfirm={async () => {
              await vigil.setRuleMode(rule.id, 'block');
              setConfirmBlock(false);
            }}
          />
        </div>
      )}
      {editing && <RuleEditorPanel id={rule.id} onClose={() => onEdit(false)} />}
    </Card>
  );
}
