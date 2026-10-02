import type { SensorEvent } from '@vigil/core';
import { EyeOff, Pencil } from 'lucide-react';
import { useState } from 'react';
import type { ExcludeScope, RuleCheck } from '../../../shared/ipc';
import { useLive, vigil } from '../api';
import { excludeScopes } from '../evidence';
import { useToast } from './Toasts';
import { Button, Card, SectionHead } from './ui';
import '../styles/rules.css';

/** "Never alert on this again" for the rule behind an alert, as an exclusion you can edit later. */
export function ExcludeFromAlert({
  alertId,
  ruleId,
  event,
  onEditRule,
}: {
  alertId: string;
  ruleId: string;
  event: SensorEvent;
  onEditRule: () => void;
}) {
  const toast = useToast();
  // Only alerts from detection rules can be excluded here.
  const [editable] = useLive(() => vigil.getRuleEditor(ruleId), ruleId);
  const [result, setResult] = useState<RuleCheck | null>(null);
  const scopes = excludeScopes(event);
  if (!editable || scopes.length === 0) return null;

  const exclude = async (scope: ExcludeScope, label: string) => {
    const r = await vigil.excludeFromAlert(alertId, scope);
    setResult(r);
    if (r.ok) toast({ text: `Excluded: ${label.toLowerCase()}` });
  };

  return (
    <Card tight>
      <SectionHead
        title="Stop alerting on this"
        sub="Adds an exclusion to the rule. It only covers what you pick, and you can remove it on the Rules page."
      />
      <div className="row" style={{ flexWrap: 'wrap' }}>
        {scopes.map((s) => (
          <Button
            key={s.scope}
            size="sm"
            kind="outline"
            icon={<EyeOff size={13} />}
            onClick={() => void exclude(s.scope, s.label)}
          >
            {s.label}
          </Button>
        ))}
        <span className="grow" />
        <Button size="sm" kind="ghost" icon={<Pencil size={13} />} onClick={onEditRule}>
          Edit rule
        </Button>
      </div>
      {result && !result.ok && (
        <div role="alert">
          <ul className="issues errors">
            {result.errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </div>
      )}
      {result?.ok && result.warnings.length > 0 && (
        <span className="t-small">{result.warnings.join(' ')}</span>
      )}
    </Card>
  );
}
