import { Check, RefreshCw, Sparkles, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import type { RuleSuggestionView, RuleSuggestionsView } from '../../../shared/ipc';
import { useLive, vigil } from '../api';
import { helperNote, PASSWORD_CANCELLED, timeAgo } from '../format';
import { draftIsToolRule } from '../rule-modes';
import { ImpactSummary, ReplaySummary } from './RuleEditor';
import { useToast } from './Toasts';
import { Button, Card, Chip, SectionHead, SeverityMark } from './ui';

const KIND: Record<RuleSuggestionView['kind'], string> = {
  new_rule: 'New rule',
  tuning: 'Narrower rule',
  retire: 'Turn down',
};

const RETIRE_TO: Record<NonNullable<RuleSuggestionView['retireTo']>, string> = {
  alert: 'Alert',
  shadow: 'Shadow',
  disabled: 'Off',
};

/** The suggestion to scroll to once Rules shows it. */
let focusOn: string | undefined;
const SHOW = 'vigil-show-suggestion';

/** Open Rules at one suggestion, e.g. from the Lead dog's card in chat. */
export function showSuggestion(id: string): void {
  focusOn = id;
  location.hash = 'rules';
  // Already on Rules, the hash doesn't change; tell the list directly.
  setTimeout(() => window.dispatchEvent(new Event(SHOW)), 0);
}

/**
 * What the AI, or Vigil from the user's own answers, suggested for the rules
 * since the user last looked. Each one was checked and replayed on this Mac's
 * last 14 days; nothing changes until the user accepts it.
 */
export function RuleSuggestions() {
  const [view, reload] = useLive(() => vigil.listRuleSuggestions());
  const [reviewing, setReviewing] = useState(false);
  const toast = useToast();
  if (!view) return null;
  const { pending, review } = view;
  if (pending.length === 0 && !review.available && !review.lastRunAt) return null;

  const reviewNow = async () => {
    setReviewing(true);
    try {
      const v = await vigil.reviewRulesNow();
      const n = v.pending.length - pending.length;
      toast({
        text: v.review.lastError
          ? `The review didn't finish: ${v.review.lastError}`
          : n > 0
            ? `${n} new suggestion${n === 1 ? '' : 's'}`
            : 'Reviewed. Nothing to change.',
      });
      reload();
    } finally {
      setReviewing(false);
    }
  };

  return (
    <Card>
      <SectionHead
        title="Suggested changes"
        sub={subtitle(review, pending.length)}
        right={
          review.available && (
            <Button
              size="sm"
              kind="ghost"
              icon={<RefreshCw size={13} className={reviewing ? 'spin' : undefined} />}
              disabled={reviewing}
              onClick={() => void reviewNow()}
            >
              {reviewing ? 'Reviewing…' : 'Review now'}
            </Button>
          )
        }
      />
      {pending.length === 0 ? (
        <span className="t-small">
          {review.lastSummary ?? 'No suggestions waiting. The AI looks again about once a day.'}
        </span>
      ) : (
        pending.map((s) => <Suggestion key={s.id} s={s} onDone={reload} />)
      )}
    </Card>
  );
}

function subtitle(review: RuleSuggestionsView['review'], pending: number): string {
  if (!review.available && pending > 0)
    return 'Checked and replayed on your last 14 days. Nothing changes until you accept.';
  if (!review.available)
    return 'Needs Claude, Codex or a cloud API key in Settings. The local model only labels events.';
  const parts = ['Checked and replayed on your last 14 days. Nothing changes until you accept.'];
  if (review.lastOkAt) parts.push(`Last review ${timeAgo(review.lastOkAt)}.`);
  return parts.join(' ');
}

function Suggestion({ s, onDone }: { s: RuleSuggestionView; onDone: () => void }) {
  const toast = useToast();
  const [showJson, setShowJson] = useState(false);
  const [focused, setFocused] = useState(false);
  const el = useRef<HTMLDivElement>(null);
  const fromVigil = s.provider === 'vigil';
  useEffect(() => {
    const show = () => {
      if (focusOn !== s.id) return;
      focusOn = undefined;
      el.current?.scrollIntoView({ block: 'center', behavior: 'smooth' });
      setFocused(true);
    };
    show();
    window.addEventListener(SHOW, show);
    return () => window.removeEventListener(SHOW, show);
  }, [s.id]);
  const accept = async () => {
    const { helper } = await vigil.acceptRuleSuggestion(s.id);
    if (helper === 'declined') {
      // Everything went back, so the suggestion is still here to accept later.
      toast({ text: `${s.ruleName}: ${PASSWORD_CANCELLED}` });
      onDone();
      return;
    }
    const done =
      s.kind === 'new_rule'
        ? `${s.ruleName} is on, in Alert mode`
        : s.kind === 'retire'
          ? `${s.ruleName} turned down to ${RETIRE_TO[s.retireTo ?? 'shadow']}`
          : `${s.ruleName} updated`;
    toast({ text: `${done}.${helperNote(helper)}` });
    onDone();
  };
  const dismiss = async () => {
    await vigil.dismissRuleSuggestion(s.id);
    toast({
      text: fromVigil
        ? 'Dismissed. Vigil won’t ask about this rule again for 30 days.'
        : 'Dismissed. The AI sees that you said no.',
    });
    onDone();
  };
  return (
    <div className={`suggestion ${focused ? 'focused' : ''}`} ref={el}>
      <div className="row">
        <Chip tone={fromVigil ? undefined : 'ai'}>
          {!fromVigil && <Sparkles size={12} />} {KIND[s.kind]}
        </Chip>
        <span className="t-h3 grow ellipsis">{s.ruleName}</span>
        {s.kind === 'new_rule' && <SeverityMark severity={s.severity as never} />}
        <span className="t-small nowrap">
          {fromVigil
            ? 'Vigil, from your answers'
            : s.by
              ? `Suggested by ${s.by} (${s.provider})`
              : s.provider}{' '}
          · {timeAgo(s.createdAt)}
        </span>
      </div>
      <p className="t-small" style={{ margin: 0 }}>
        {s.rationale}
      </p>
      {s.condition && <div className="subject mono">Matches when {s.condition}</div>}
      {s.exclusion && <div className="subject mono">Stop matching when {s.exclusion}</div>}
      {s.kind === 'retire' && (
        <div className="subject">
          {s.retireTo === 'disabled'
            ? 'Turn this rule off.'
            : s.retireTo === 'alert'
              ? 'Alert instead of blocking.'
              : 'Keep recording matches in Shadow, without alerts.'}
        </div>
      )}
      {s.tuning && (
        <span className="t-small">
          On your last 14 days: {s.tuning.hitsBefore} matches before, {s.tuning.hitsAfter} after.
        </span>
      )}
      {s.impact && s.kind !== 'new_rule' && <ImpactSummary impact={s.impact} />}
      {s.kind !== 'tuning' && s.replay && (
        <ReplaySummary
          replay={s.replay}
          toolRule={s.ruleJson ? draftIsToolRule(s.ruleJson) : false}
        />
      )}
      {s.evidence.length > 0 && (
        <ul className="t-small evidence">
          {s.evidence.slice(0, 5).map((e) => (
            <li key={e}>{e}</li>
          ))}
        </ul>
      )}
      {s.warnings.map((w) => (
        <span key={w} className="t-small warn-text">
          {w}
        </span>
      ))}
      {showJson && s.ruleJson && <pre className="rule-json">{s.ruleJson}</pre>}
      <div className="row">
        <Button kind="primary" size="sm" icon={<Check size={14} />} onClick={() => void accept()}>
          {s.kind === 'new_rule' ? 'Turn on (Alert)' : s.kind === 'retire' ? 'Turn down' : 'Apply'}
        </Button>
        <Button size="sm" kind="ghost" icon={<X size={14} />} onClick={() => void dismiss()}>
          Dismiss
        </Button>
        {s.ruleJson && (
          <Button size="sm" kind="ghost" onClick={() => setShowJson(!showJson)}>
            {showJson ? 'Hide rule' : 'Show rule'}
          </Button>
        )}
      </div>
    </div>
  );
}
