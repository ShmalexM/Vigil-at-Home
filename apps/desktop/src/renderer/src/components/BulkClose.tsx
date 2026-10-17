import { useState } from 'react';
import { useLive, vigil } from '../api';
import { useToast } from './Toasts';
import { Button } from './ui';

const STAYS =
  'They move to History as expected. Nothing is released, and rules stay as they are. Any with something blocked, an action taken or a suggestion waiting stay open.';

/**
 * A bulk close behind a confirm. Only alerts last seen before the confirm
 * opened are closed, so anything that turns up while the user reads it stays;
 * the main process checks every alert again before closing it.
 */
function ConfirmClose({
  label,
  question,
  count,
  close,
}: {
  label: string;
  question: string;
  count: number;
  close: (at: number) => Promise<number>;
}) {
  const toast = useToast();
  const [at, setAt] = useState<number>();
  const [busy, setBusy] = useState(false);
  if (at === undefined) {
    return (
      <Button size="sm" kind="ghost" onClick={() => setAt(Date.now())}>
        {label}
      </Button>
    );
  }
  return (
    <div className="row noticed-confirm" role="group" aria-label="Confirm">
      <span className="t-small grow">
        {question} {STAYS}
      </span>
      <Button size="sm" kind="ghost" onClick={() => setAt(undefined)}>
        Cancel
      </Button>
      <Button
        size="sm"
        kind="primary"
        disabled={busy}
        autoFocus
        onClick={async () => {
          setBusy(true);
          try {
            const n = await close(at);
            toast({ text: `Closed ${n} ${n === 1 ? 'alert' : 'alerts'}` });
          } finally {
            setBusy(false);
            setAt(undefined);
          }
        }}
      >
        Close {count === 1 ? 'it' : `all ${count}`}
      </Button>
    </div>
  );
}

/** "Close all from this rule", on an open alert whose rule has others open. */
export function CloseRuleAlerts({ ruleId, ruleName }: { ruleId: string; ruleName: string }) {
  const [n] = useLive(() => vigil.bulkClosable(ruleId), ruleId);
  const count = n?.rule ?? 0;
  if (count < 2) return null;
  return (
    <ConfirmClose
      label={`Close all ${count} from this rule`}
      question={`Close all ${count} open alerts from “${ruleName}”?`}
      count={count}
      close={(at) => vigil.closeRuleAlerts(ruleId, at)}
    />
  );
}

/** "Close my agents' alerts older than 7 days", shown while there are some. */
export function CloseOldAgentAlerts() {
  const [n] = useLive(() => vigil.bulkClosable());
  const count = n?.oldAgents ?? 0;
  if (count === 0) return null;
  return (
    <div className="row wrap" style={{ gap: 8 }}>
      <span className="t-small grow">
        {count === 1
          ? 'One alert from your AI agents is'
          : `${count.toLocaleString()} alerts from your AI agents are`}{' '}
        more than a week old.
      </span>
      <ConfirmClose
        label="Close my agents’ alerts older than 7 days"
        question={`Close ${count === 1 ? 'it' : `all ${count.toLocaleString()}`}?`}
        count={count}
        close={(at) => vigil.closeOldAgentAlerts(at)}
      />
    </div>
  );
}
