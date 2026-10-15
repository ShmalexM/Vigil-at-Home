import type { Action, ActionResult } from '@vigil/core';

/**
 * Carries out a response action. The real implementation talks to the
 * privileged helper and Santa (built in the sensors package). Callers have
 * already checked `authorizeAction`; implementations should check it again.
 */
export interface ActionExecutor {
  execute(action: Action): Promise<ActionResult>;
  /** True while actions are only simulated (no helper yet). */
  readonly simulated?: boolean;
  /** Ask once for the password for rule changes held for the next dialog (HelperLink). */
  approveHeld?(): Promise<void>;
  /** Refuse those held rule changes without asking (HelperLink). */
  dropHeld?(): void;
}

/** Records what would happen without touching the system. Used until the helper is installed. */
export class DryRunExecutor implements ActionExecutor {
  readonly log: Action[] = [];
  readonly simulated = true;

  async execute(action: Action): Promise<ActionResult> {
    this.log.push(action);
    const at = Date.now();
    return action.kind === 'file.quarantine'
      ? { at, quarantineId: `dry-${at}`, simulated: true }
      : { at, simulated: true };
  }
}
