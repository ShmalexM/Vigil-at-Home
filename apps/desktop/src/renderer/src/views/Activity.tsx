import { useLive, vigil } from '../api';
import { useToast } from '../components/Toasts';
import { Button, Card, Chip, StatusMark } from '../components/ui';
import { actorLabel, clock, describeAction } from '../format';
import { PageHead } from './AppShell';

const UNDOABLE = new Set([
  'process.suspend',
  'network.block',
  'file.quarantine',
  'santa.rule.set',
  'persistence.disable',
]);

export function ActivityView() {
  const [actions] = useLive(() => vigil.listActions());
  const toast = useToast();
  return (
    <div className="page">
      <PageHead
        title="Activity"
        purpose="Every action Vigil took or you asked for, with who asked and why. Anything that can be undone can be undone here."
      />
      <Card>
        {(actions ?? []).length === 0 && <span className="t-small">No actions yet.</span>}
        {(actions ?? []).map((r) => (
          <div key={r.id} className="row activity-row">
            <StatusMark
              state={
                r.status === 'done'
                  ? 'done'
                  : r.status === 'pending'
                    ? 'running'
                    : r.status === 'undone'
                      ? 'warn'
                      : 'failed'
              }
              label={r.status}
            />
            <div className="col grow" style={{ gap: 1 }}>
              <span className="ellipsis">{describeAction(r.action)}</span>
              <span className="t-small ellipsis">
                {r.reason}
                {r.result?.error ? ` · ${r.result.error}` : ''}
              </span>
            </div>
            <Chip tone={r.actor === 'user' ? 'accent' : r.actor === 'ai' ? 'ai' : undefined}>
              {actorLabel(r.actor)}
            </Chip>
            <span className="t-small" style={{ width: 150, textAlign: 'right' }}>
              {clock(r.requestedAt)}
            </span>
            {r.status === 'done' && !r.undoes && UNDOABLE.has(r.action.kind) ? (
              <Button
                size="sm"
                kind="ghost"
                onClick={async () => {
                  await vigil.undoAction(r.id);
                  toast({ text: `Undone: ${describeAction(r.action)}` });
                }}
              >
                Undo
              </Button>
            ) : (
              <span style={{ width: 54 }} />
            )}
          </div>
        ))}
      </Card>
    </div>
  );
}
