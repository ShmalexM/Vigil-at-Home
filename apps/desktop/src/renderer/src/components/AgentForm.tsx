import { Check, Plus, Save, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  AGENT_KIND_LABEL,
  type AgentCandidate,
  type AgentDetail,
  type AgentKind,
  type AgentMatchPreview,
  type AgentView,
} from '../../../shared/agents';
import { vigil } from '../api';
import { timeAgo } from '../format';
import {
  MATCHER_FIELDS,
  MAX_MATCHERS,
  agentIdFor,
  describeMatcher,
  emptyRow,
  matchersFromRows,
  plural,
  rowsFromMatchers,
  type MatcherField,
  type MatcherRow,
} from '../views/agents-format';
import { useToast } from './Toasts';
import { Button, IconButton, SectionHead, Segmented } from './ui';

const KINDS = Object.entries(AGENT_KIND_LABEL) as [AgentKind, string][];

const KIND_NOTE: Partial<Record<AgentKind, string>> = {
  ide: 'Editors usually stay unwatched: their built-in terminal runs your own commands too.',
  runtime: 'Model runtimes are listed only. Vigil never tags what they run.',
};

/**
 * Add an agent by hand, or change how Vigil recognises one. Pick a program
 * Vigil saw recently or type its name, path or signer; Vigil then counts what
 * those matchers would have caught over the last 14 days before you save.
 */
export function AgentForm({
  agents,
  initial,
  onClose,
  onSaved,
}: {
  /** Every agent, so a new one gets an id of its own. */
  agents: readonly AgentView[];
  /** The agent being edited; a new agent when absent. */
  initial?: AgentDetail;
  onClose: () => void;
  onSaved: (agent: AgentView) => void;
}) {
  const toast = useToast();
  const start = rowsFromMatchers(initial?.match ?? []);
  const [name, setName] = useState(initial?.name ?? '');
  const [kind, setKind] = useState<AgentKind>(initial?.kind ?? 'cli');
  const [watch, setWatch] = useState(initial?.watch ?? true);
  const [rows, setRows] = useState<MatcherRow[]>(
    start.rows.length || start.kept.length ? start.rows : [emptyRow()],
  );
  const kept = start.kept;
  const [preview, setPreview] = useState<{ key: string; result: AgentMatchPreview } | null>(null);
  const [errors, setErrors] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [candidates, setCandidates] = useState<AgentCandidate[]>();

  // Recent programs to pick from: loaded once when the form opens, not on every change.
  useEffect(() => {
    if (initial) return;
    let live = true;
    vigil.listAgentCandidates().then(
      (c) => live && setCandidates(c),
      (err: unknown) => console.error(err),
    );
    return () => {
      live = false;
    };
  }, [initial]);

  const { match, errors: rowErrors } = matchersFromRows(rows, kept);
  const key = JSON.stringify(match);
  const current = preview?.key === key ? preview.result : null;

  const check = async (rs: MatcherRow[] = rows) => {
    const m = matchersFromRows(rs, kept);
    setErrors(m.errors);
    if (m.errors.length) return;
    setBusy(true);
    try {
      setPreview({ key: JSON.stringify(m.match), result: await vigil.previewAgentMatch(m.match) });
    } catch (err) {
      setErrors([err instanceof Error ? err.message : String(err)]);
    } finally {
      setBusy(false);
    }
  };

  const save = async () => {
    const trimmed = name.trim();
    const problems = [
      ...(trimmed.length === 0 ? ['Give the agent a name.'] : []),
      ...(trimmed.length > 60 ? ['Keep the name to 60 characters.'] : []),
      ...rowErrors,
    ];
    setErrors(problems);
    if (problems.length) return;
    const id = initial?.id ?? agentIdFor(trimmed, new Set(agents.map((a) => a.id)));
    const r = await vigil.saveAgent({
      id,
      name: trimmed,
      kind,
      match,
      watch,
      ...(initial?.note !== undefined ? { note: initial.note } : {}),
    });
    if (!r.ok) {
      setErrors(r.errors);
      return;
    }
    toast({ text: initial ? `${trimmed} updated` : `${trimmed} added` });
    onSaved(r.agent);
  };

  const pick = (c: AgentCandidate) => {
    const next: MatcherRow[] = [{ field: 'paths', value: c.path, args: '' }];
    if (!name.trim()) setName(c.name.slice(0, 60));
    if (c.path.includes('.app/')) setKind('app');
    setRows(next);
    void check(next);
  };

  const setRow = (i: number, patch: Partial<MatcherRow>) =>
    setRows(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  return (
    <div className="col agent-form" style={{ gap: 14 }}>
      <SectionHead
        title={initial ? `How Vigil recognises ${initial.name}` : 'Add an agent'}
        sub="Vigil tags everything this program starts, so the agent rules can tell its commands from yours. Before you save, it counts what these matchers would have caught over the last 14 days."
        right={
          <IconButton label="Close" onClick={onClose}>
            <X size={15} />
          </IconButton>
        }
      />

      {!initial && (
        <div className="col" style={{ gap: 6 }}>
          <span className="t-label">Pick a program Vigil saw in the last day</span>
          {candidates === undefined ? (
            <span className="t-small">Looking…</span>
          ) : candidates.length === 0 ? (
            <span className="t-small">
              No programs outside the known agents ran in the last day. Type how to recognise it
              below instead.
            </span>
          ) : (
            <div className="candidate-list scroll">
              {candidates.map((c) => (
                <button key={c.path} type="button" className="list-row" onClick={() => pick(c)}>
                  <span className="col grow" style={{ gap: 0 }}>
                    <span className="t-h3 ellipsis">{c.name}</span>
                    <span className="t-small mono ellipsis">{c.path}</span>
                  </span>
                  <span className="t-small nowrap">
                    {plural(c.count, 'launch', 'launches')} · {timeAgo(c.lastSeen)}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="agent-form-grid">
        <label className="col" style={{ gap: 4 }}>
          <span className="t-label">Name</span>
          <input
            className="field"
            value={name}
            maxLength={60}
            placeholder="Goose"
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <label className="col" style={{ gap: 4 }}>
          <span className="t-label">Kind</span>
          <select
            className="field"
            value={kind}
            onChange={(e) => setKind(e.target.value as AgentKind)}
          >
            {KINDS.map(([k, label]) => (
              <option key={k} value={k}>
                {label}
              </option>
            ))}
          </select>
        </label>
      </div>
      {KIND_NOTE[kind] && <span className="t-small">{KIND_NOTE[kind]}</span>}

      <div className="col" style={{ gap: 6 }}>
        <span className="t-label">How Vigil recognises it</span>
        <span className="t-small">
          Any one row is enough. Commas mean “any of these”. A command-line pattern narrows its row,
          for agents that run under node: <code>*@openai/codex*</code>.
        </span>
        {kept.map((m, i) => (
          <div key={`kept-${i}`} className="excl-row">
            <span className="grow mono">{describeMatcher(m)}</span>
            <span className="t-small">kept as it is</span>
          </div>
        ))}
        {rows.map((r, i) => (
          <div key={i} className="matcher-row">
            <select
              className="field"
              aria-label="What to match"
              value={r.field}
              onChange={(e) => setRow(i, { field: e.target.value as MatcherField })}
            >
              {MATCHER_FIELDS.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </select>
            <input
              className="field mono"
              aria-label="Value"
              placeholder={MATCHER_FIELDS.find((f) => f.value === r.field)?.placeholder}
              value={r.value}
              onChange={(e) => setRow(i, { value: e.target.value })}
            />
            <input
              className="field mono"
              aria-label="Command line pattern (optional)"
              placeholder="Command line like (optional)"
              value={r.args}
              onChange={(e) => setRow(i, { args: e.target.value })}
            />
            <IconButton
              size="sm"
              label="Remove this row"
              disabled={rows.length + kept.length <= 1}
              onClick={() => setRows(rows.filter((_, j) => j !== i))}
            >
              <X size={14} />
            </IconButton>
          </div>
        ))}
        <div className="row">
          <Button
            size="sm"
            kind="ghost"
            icon={<Plus size={14} />}
            disabled={rows.length + kept.length >= MAX_MATCHERS}
            onClick={() => setRows([...rows, emptyRow()])}
          >
            Add another way
          </Button>
        </div>
      </div>

      <div className="row spread preflight-option">
        <div className="col" style={{ gap: 2 }}>
          <span className="t-h3">Watch what it starts</span>
          <span className="t-small">
            On: the programs it runs are tagged and the agent rules apply to them.
          </span>
        </div>
        <Segmented
          label="Watch what it starts"
          value={watch ? 'on' : 'off'}
          options={[
            { value: 'off', label: 'Off' },
            { value: 'on', label: 'On' },
          ]}
          onChange={(v) => setWatch(v === 'on')}
        />
      </div>

      {errors.length > 0 && (
        <ul className="issues errors">
          {errors.map((e) => (
            <li key={e}>{e}</li>
          ))}
        </ul>
      )}
      {current && <PreviewSummary preview={current} />}

      <div className="row" style={{ flexWrap: 'wrap' }}>
        <Button icon={<Check size={14} />} disabled={busy} onClick={() => void check()}>
          {busy ? 'Checking…' : 'Check'}
        </Button>
        <Button
          kind="primary"
          icon={<Save size={14} />}
          disabled={!current}
          title={current ? undefined : 'Check the matchers first'}
          onClick={() => void save()}
        >
          Save
        </Button>
        <Button kind="ghost" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

function PreviewSummary({ preview: p }: { preview: AgentMatchPreview }) {
  return (
    <div className="col" style={{ gap: 6 }}>
      <span className="t-small">
        {p.execs === 0
          ? 'Nothing matched in the last 14 days. You can still save it: Vigil watches from now on.'
          : `Would have matched ${plural(p.execs, 'program launch', 'program launches')} in the last 14 days, in ${plural(p.trees, 'separate run')}.`}
        {p.truncated &&
          ' Vigil stopped counting at its scan limit, so there were at least this many.'}
      </span>
      {p.samples.map((s) => (
        <div key={s} className="excl-row">
          <span className="grow mono ellipsis" title={s}>
            {s}
          </span>
        </div>
      ))}
    </div>
  );
}
