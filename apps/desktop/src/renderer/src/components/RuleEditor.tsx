import { Check, Pencil, Plus, RotateCcw, Trash2, X } from 'lucide-react';
import { useState } from 'react';
import type {
  ExclusionInput,
  ImpactPreview,
  ReplayPreview,
  RuleCheck,
  RuleEditorView,
} from '../../../shared/ipc';
import { useLive, vigil } from '../api';
import { timeAgo } from '../format';
import { draftIsToolRule, replayLine, replaySampleRow } from '../rule-modes';
import { HoldButton } from './HoldButton';
import { useToast } from './Toasts';
import { Button, Chip, IconButton } from './ui';
import { computer } from '../platform';

/** Fields people usually exclude on, shown first in the picker. */
const COMMON_FIELDS = [
  'process.path',
  'process.name',
  'process.teamId',
  'process.signingId',
  'process.sha256',
  'process.parentName',
  'process.commandLine',
  'remoteHost',
  'remoteAddress',
  'path',
];

const OPS: { value: ExclusionInput['op']; label: string }[] = [
  { value: 'eq', label: 'is' },
  { value: 'startsWith', label: 'starts with' },
  { value: 'endsWith', label: 'ends with' },
  { value: 'contains', label: 'contains' },
  { value: 'glob', label: 'matches (* wildcards)' },
  { value: 'in', label: 'is one of (a, b)' },
];

export const NEW_RULE_TEMPLATE = JSON.stringify(
  {
    id: 'my-rule',
    name: 'My rule',
    description: 'What this rule looks for, in a sentence.',
    mode: 'shadow',
    severity: 'medium',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: { field: 'process.name', op: 'eq', value: 'example' },
    exclusions: [],
    response: [],
    reasons: ['{{process.name}} ran.'],
  },
  null,
  2,
);

/** The editor panel under a rule: exclusions first, then the full rule as JSON. */
export function RuleEditorPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const [view, reload] = useLive(() => vigil.getRuleEditor(id), id);
  if (view === undefined) return null;
  if (view === null) return <span className="t-small">This rule can't be edited here.</span>;
  return (
    <div className="editor">
      <Exclusions view={view} reload={reload} />
      <JsonEditor
        key={view.ruleJson}
        initial={view.ruleJson}
        view={view}
        onSaved={reload}
        onClose={onClose}
      />
    </div>
  );
}

/** A brand-new rule: just the JSON editor, starting from a template (`initial`, or a blank rule). */
export function NewRulePanel({ onClose, initial }: { onClose: () => void; initial?: string }) {
  return (
    <div className="editor">
      <JsonEditor initial={initial ?? NEW_RULE_TEMPLATE} onSaved={onClose} onClose={onClose} />
    </div>
  );
}

function Exclusions({ view, reload }: { view: RuleEditorView; reload: () => void }) {
  const toast = useToast();
  const [draft, setDraft] = useState<ExclusionInput>({
    field: 'process.path',
    op: 'eq',
    value: '',
  });
  const [issues, setIssues] = useState<RuleCheck | null>(null);
  const fields = [
    ...COMMON_FIELDS,
    ...view.fields.filter((f) => !COMMON_FIELDS.includes(f)).sort(),
  ];

  const add = async () => {
    const r = await vigil.addExclusion(view.rule.id, { ...draft, value: draft.value.trim() });
    setIssues(r.ok && r.warnings.length === 0 ? null : r);
    if (r.ok) {
      setDraft({ ...draft, value: '' });
      toast({ text: 'Exclusion added' });
      reload();
    }
  };

  return (
    <div className="col" style={{ gap: 8 }}>
      <div className="col" style={{ gap: 2 }}>
        <span className="t-h3">Exclusions</span>
        <span className="t-small">
          The rule never fires when one of these matches. Keep them narrow: a program's path or
          signer, not a whole folder.
        </span>
      </div>
      {view.exclusions.length === 0 && view.exceptions.length === 0 && (
        <span className="t-small">None yet.</span>
      )}
      {view.exclusions.map((text, i) => (
        <div key={`x${i}`} className="excl-row">
          <span className="grow mono">{text}</span>
          <IconButton
            size="sm"
            label="Remove exclusion"
            onClick={async () => {
              const r = await vigil.removeExclusion(view.rule.id, i);
              if (!r.ok) setIssues(r);
              reload();
            }}
          >
            <X size={14} />
          </IconButton>
        </div>
      ))}
      {view.exceptions.map((x) => (
        <div key={x.id} className="excl-row">
          <span className="grow">
            <span className="mono">{x.summary}</span>
            <span className="t-small"> · marked fine from an alert {timeAgo(x.createdAt)}</span>
          </span>
          <IconButton
            size="sm"
            label="Remove"
            onClick={async () => {
              await vigil.removeException(x.id);
              reload();
            }}
          >
            <X size={14} />
          </IconButton>
        </div>
      ))}
      <div className="excl-form">
        <select
          className="field"
          aria-label="Field"
          value={draft.field}
          onChange={(e) => setDraft({ ...draft, field: e.target.value })}
        >
          {fields.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
        <select
          className="field"
          aria-label="How it matches"
          value={draft.op}
          onChange={(e) => setDraft({ ...draft, op: e.target.value as ExclusionInput['op'] })}
        >
          {OPS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <input
          className="field"
          aria-label="Value"
          placeholder="/Applications/Docker.app/Contents/MacOS/com.docker.backend"
          value={draft.value}
          onChange={(e) => setDraft({ ...draft, value: e.target.value })}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && draft.value.trim()) void add();
          }}
        />
        <Button
          size="sm"
          icon={<Plus size={14} />}
          disabled={!draft.value.trim()}
          onClick={() => void add()}
        >
          Add
        </Button>
      </div>
      {issues && <Issues check={issues} />}
    </div>
  );
}

function JsonEditor({
  initial,
  view,
  onSaved,
  onClose,
}: {
  initial: string;
  view?: RuleEditorView;
  onSaved: () => void;
  onClose: () => void;
}) {
  const toast = useToast();
  const [text, setText] = useState(initial);
  const [checked, setChecked] = useState<{ text: string; result: RuleCheck } | null>(null);
  const [busy, setBusy] = useState(false);
  const current = checked?.text === text ? checked.result : null;

  const check = async () => {
    setBusy(true);
    try {
      setChecked({ text, result: await vigil.previewRule(text) });
    } finally {
      setBusy(false);
    }
  };

  const save = async () => {
    const r = await vigil.saveRule(text);
    setChecked({ text, result: r });
    if (r.ok) {
      toast({ text: 'Rule saved' });
      onSaved();
    }
  };

  return (
    <div className="col" style={{ gap: 8 }}>
      <div className="col" style={{ gap: 2 }}>
        <span className="t-h3">{view ? 'Rule' : 'New rule'}</span>
        <span className="t-small">
          The whole rule as JSON. Check it first: Vigil replays it over the last 14 days on this{' '}
          {computer}
          so you can see how often it would have fired before you save.
        </span>
      </div>
      <textarea
        className="field rule-json"
        spellCheck={false}
        aria-label="Rule JSON"
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      {current && <Issues check={current} />}
      {current?.impact && <ImpactSummary impact={current.impact} />}
      {current?.replay && (
        <ReplaySummary replay={current.replay} toolRule={draftIsToolRule(text)} />
      )}
      <div className="row" style={{ flexWrap: 'wrap' }}>
        <Button icon={<Check size={14} />} disabled={busy} onClick={() => void check()}>
          {busy ? 'Checking…' : 'Check'}
        </Button>
        <Button
          kind="primary"
          icon={<Pencil size={14} />}
          disabled={!current?.ok}
          title={current?.ok ? undefined : 'Check the rule first'}
          onClick={() => void save()}
        >
          Save
        </Button>
        <Button kind="ghost" onClick={onClose}>
          Close
        </Button>
        <span className="grow" />
        {view?.edited && (
          <HoldButton
            size="sm"
            icon={<RotateCcw size={13} />}
            label="Hold to restore the shipped rule"
            doneLabel="Restored"
            onConfirm={async () => {
              await vigil.revertRule(view.rule.id);
              toast({ text: 'Restored the shipped version' });
              onSaved();
            }}
          />
        )}
        {view && !view.builtin && (
          <HoldButton
            size="sm"
            icon={<Trash2 size={13} />}
            label="Hold to delete"
            doneLabel="Deleted"
            onConfirm={async () => {
              await vigil.deleteRule(view.rule.id);
              toast({ text: 'Rule deleted' });
              onClose();
            }}
          />
        )}
      </div>
      {view?.builtinUpdateAvailable && (
        <span className="t-small">
          Vigil shipped a newer version of this rule. Your edit is still in use; restore the shipped
          rule to get the update.
        </span>
      )}
    </div>
  );
}

function Issues({ check }: { check: RuleCheck }) {
  return (
    <>
      {check.errors.length > 0 && (
        <div role="alert">
          <ul className="issues errors">
            {check.errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </div>
      )}
      {check.warnings.length > 0 && (
        <ul className="issues warnings">
          {check.warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}
    </>
  );
}

const VERDICT: Record<string, { label: string; tone?: 'good' | 'fair' | 'poor' }> = {
  never_fired: { label: 'Never fired' },
  quiet: { label: 'Quiet', tone: 'good' },
  ok: { label: 'Reasonable', tone: 'good' },
  noisy: { label: 'Noisy', tone: 'poor' },
};

const IMPACT: Record<ImpactPreview['verdict'], { label: string; tone: 'good' | 'fair' | 'poor' }> =
  {
    no_loss: { label: 'Loses nothing', tone: 'good' },
    narrow: { label: 'Narrow', tone: 'good' },
    broad: { label: 'Check before approving', tone: 'poor' },
  };

/** What approving would stop catching, above the replay, so the cost is read first. */
export function ImpactSummary({ impact }: { impact: ImpactPreview }) {
  const v = IMPACT[impact.verdict];
  return (
    <div className="col impact" style={{ gap: 6 }}>
      <div className="row">
        <Chip tone={v.tone}>{v.label}</Chip>
        <span className="t-small">What this change would stop catching</span>
      </div>
      {impact.findings.map((f) => (
        <span key={f} className={impact.verdict === 'broad' ? 't-small warn-text' : 't-small'}>
          {f}
        </span>
      ))}
      {impact.stopsAlertingOn.slice(0, 5).map((s) => (
        <div key={s.what} className="excl-row">
          <span className="grow mono ellipsis">{s.what}</span>
          {s.untrusted && <Chip tone="fair">unsigned</Chip>}
          <span className="t-small nowrap">
            {s.events} event{s.events === 1 ? '' : 's'}
          </span>
        </div>
      ))}
    </div>
  );
}

/** `toolRule`: the rule answers Claude Code's hook, so it counts steps, not alerts or programs. */
export function ReplaySummary({
  replay: r,
  toolRule = false,
}: {
  replay: ReplayPreview;
  toolRule?: boolean;
}) {
  const v = VERDICT[r.verdict] ?? { label: r.verdict };
  return (
    <div className="col" style={{ gap: 6 }}>
      <div className="row">
        <Chip {...(v.tone ? { tone: v.tone } : {})}>{v.label}</Chip>
        <span className="t-small">{replayLine(r, toolRule)}</span>
      </div>
      {r.notes.map((n) => (
        <span key={n} className="t-small">
          {n}
        </span>
      ))}
      {r.samples.slice(0, 5).map((s, i) => {
        const row = replaySampleRow(s, toolRule);
        return (
          <div key={i} className="excl-row">
            <span className="t-small nowrap">{timeAgo(s.ts)}</span>
            <span className="grow mono ellipsis" title={row.what}>
              {row.what}
            </span>
            <span className="t-small">{row.note}</span>
          </div>
        );
      })}
    </div>
  );
}
