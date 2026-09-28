import type { SensorEvent } from '@vigil/core';
import { EyeOff, Pencil } from 'lucide-react';
import { useState } from 'react';
import type { ExcludeScope, RuleCheck } from '../../../shared/ipc';
import { useLive, vigil } from '../api';
import { useToast } from './Toasts';
import { Button, Card, SectionHead } from './ui';
import '../styles/rules.css';

/** The scopes this event has enough detail for, narrowest first. */
function scopesFor(e: SensorEvent): { scope: ExcludeScope; label: string }[] {
  const out: { scope: ExcludeScope; label: string }[] = [];
  const p = 'process' in e ? e.process : undefined;
  if (p) out.push({ scope: 'this_binary', label: 'This program' });
  if (p?.teamId && p.signingId)
    out.push({ scope: 'this_signer', label: 'Anything from this signer' });
  if (e.kind === 'network.connection') out.push({ scope: 'this_host', label: 'This site' });
  if (!p && 'path' in e && e.path) out.push({ scope: 'this_path', label: 'This file' });
  return out;
}

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
  const scopes = scopesFor(event);
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
        <ul className="issues errors">
          {result.errors.map((e) => (
            <li key={e}>{e}</li>
          ))}
        </ul>
      )}
      {result?.ok && result.warnings.length > 0 && (
        <span className="t-small">{result.warnings.join(' ')}</span>
      )}
    </Card>
  );
}
