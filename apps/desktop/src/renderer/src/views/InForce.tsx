import { ShieldCheck, TriangleAlert, Unlock } from 'lucide-react';
import { useState } from 'react';
import type { InForceItem } from '../../../shared/in-force';
import { useLive, vigil } from '../api';
import { useToast } from '../components/Toasts';
import { Button, Card, Chip, SectionHead } from '../components/ui';
import { computer } from '../platform';
import { PageHead } from './AppShell';
import {
  FLAG_LABEL,
  FLAG_WHY,
  KIND_LABEL,
  ageWords,
  groupItems,
  untilWords,
} from './in-force-format';

/**
 * Everything Vigil is enforcing right now, with what caused it and a way to
 * release it. Every release asks for the admin password, like an alert's.
 */
export function InForceView({ go }: { go: (r: string) => void }) {
  const [view] = useLive(() => vigil.getInForce());
  if (!view) return null;
  const groups = groupItems(view.items);

  return (
    <div className="page">
      <PageHead
        title="In force"
        purpose={`Everything Vigil is blocking, pausing or holding on this ${computer} right now, and why. Releasing anything asks for your password.`}
      />
      {view.helper === 'unavailable' && (
        <div className="attn fair" role="status">
          <TriangleAlert size={17} />
          <span>
            Vigil’s helper isn’t running, so this is Vigil’s own record and may be out of date.
            Nothing can be released until the helper is back.
          </span>
        </div>
      )}
      {view.check && (
        <div className="attn poor" role="status">
          <TriangleAlert size={17} />
          <span>{view.check.message}</span>
        </div>
      )}
      {groups.length === 0 && (
        <Card>
          <div className="row">
            <ShieldCheck size={18} color="var(--good)" aria-hidden />
            <span>Nothing is blocked or held right now. Vigil is only watching.</span>
          </div>
        </Card>
      )}
      {groups.map(([kind, items]) => (
        <Card key={kind}>
          <SectionHead title={KIND_LABEL[kind]} />
          <div className="list">
            {items.map((item) => (
              <InForceRow key={item.key} item={item} go={go} />
            ))}
          </div>
        </Card>
      ))}
    </div>
  );
}

function InForceRow({ item, go }: { item: InForceItem; go: (r: string) => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const age = ageWords(item.since);
  const until = untilWords(item.until);
  const cause = item.cause;
  const release = async () => {
    setBusy(true);
    try {
      const out = await vigil.releaseInForce(item.key);
      toast({ text: out.ok ? 'Released' : (out.error ?? 'Not released') });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="list-row" style={{ alignItems: 'flex-start' }}>
      <span className="grow col" style={{ gap: 3, minWidth: 0 }}>
        <span className="t-h3 clamp-2" title={item.title}>
          {item.title}
        </span>
        {item.detail && (
          <span className="t-small mono" style={{ overflowWrap: 'anywhere' }}>
            {item.detail}
          </span>
        )}
        <span className="t-small">
          {[age && `In force ${age}`, until].filter(Boolean).join(' · ')}
          {cause?.alertId && (
            <>
              {age || until ? ' · ' : ''}
              <a
                href={`#alerts/${cause.alertId}`}
                onClick={(e) => {
                  e.preventDefault();
                  go(`alerts/${cause.alertId}`);
                }}
              >
                {cause.alertTitle ?? 'See the alert'}
              </a>
            </>
          )}
          {!cause?.alertId && cause?.ruleId && (
            <>
              {age || until ? ' · ' : ''}
              <a
                href={`#rules/${cause.ruleId}`}
                onClick={(e) => {
                  e.preventDefault();
                  go(`rules/${cause.ruleId}`);
                }}
              >
                Rule: {cause.ruleName ?? cause.ruleId}
              </a>
            </>
          )}
          {cause?.byYou && ' · You asked for this'}
          {!cause && ' · Vigil has no record of why'}
        </span>
        {item.flags.map((f) => (
          <span key={f} className="t-small">
            {FLAG_WHY[f]}
          </span>
        ))}
      </span>
      <span className="col" style={{ gap: 6, alignItems: 'flex-end' }}>
        {item.flags.map((f) => (
          <Chip key={f} tone="poor">
            {FLAG_LABEL[f]}
          </Chip>
        ))}
        {item.release === 'release' ? (
          <Button size="sm" icon={<Unlock size={14} />} disabled={busy} onClick={release}>
            {busy ? 'Waiting for your password…' : 'Release'}
          </Button>
        ) : (
          cause?.ruleId && (
            <Button size="sm" kind="ghost" onClick={() => go(`rules/${cause.ruleId}`)}>
              Change the rule
            </Button>
          )
        )}
      </span>
    </div>
  );
}
