import type { RuleMode } from '@vigil/core';
import { useState } from 'react';
import type { RuleView } from '../../../shared/ipc';
import { useLive, vigil } from '../api';
import { HoldButton } from '../components/HoldButton';
import { useToast } from '../components/Toasts';
import { Card, Chip, Segmented, SeverityMark } from '../components/ui';
import { PageHead } from './AppShell';

const MODES: { value: RuleMode; label: string }[] = [
  { value: 'disabled', label: 'Off' },
  { value: 'shadow', label: 'Shadow' },
  { value: 'alert', label: 'Alert' },
  { value: 'block', label: 'Block' },
];

export function RulesView() {
  const [rules] = useLive(() => vigil.listRules());
  const [filter, setFilter] = useState<'all' | 'review'>('all');
  const list = (rules ?? []).filter((r) => filter === 'all' || r.rule.mode === 'shadow');

  return (
    <div className="page">
      <PageHead
        title="Rules"
        purpose="Rules decide instantly and offline; the AI never blocks on its own. New and AI-drafted rules start in Shadow, where they only log matches. Promote one when its matches look right."
        right={
          <Segmented
            label="Filter"
            value={filter}
            onChange={setFilter}
            options={[
              { value: 'all', label: 'All' },
              { value: 'review', label: 'In shadow' },
            ]}
          />
        }
      />
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
            <RuleRow key={r.rule.id} view={r} />
          ))}
        </div>
      )}
    </div>
  );
}

function RuleRow({ view }: { view: RuleView }) {
  const { rule, matches7d } = view;
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
          <span className="t-small ellipsis">{rule.description}</span>
        </div>
        <SeverityMark severity={rule.severity} />
        <Chip title="How often this rule is expected to be right">{rule.fidelity} fidelity</Chip>
        <span className="t-small" style={{ width: 96, textAlign: 'right' }}>
          {matches7d} match{matches7d === 1 ? '' : 'es'} / 7d
        </span>
        <Segmented
          label={`Mode for ${rule.name}`}
          value={rule.mode}
          options={MODES}
          onChange={(m) => void set(m)}
        />
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
    </Card>
  );
}
