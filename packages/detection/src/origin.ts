/**
 * Proof that a call came from the person at the keyboard.
 *
 * Only the app's UI handlers (a click in the popup or console) should mint
 * one, through `@vigil/detection/user`. The AI tool handlers import only the
 * package root, which does not export the factory, so nothing an agent can
 * call is able to approve a rule, allow a program or promote a stage.
 *
 * This is a code-structure guard inside one process, not a sandbox: it keeps
 * the approval path explicit and auditable. The real boundary is that the
 * agent is only ever handed the propose/read tools in proposals/tools.ts.
 */
const issued = new WeakSet<object>();

export interface UserOrigin {
  readonly kind: "user";
  /** Which UI surface the click came from, for the audit log. */
  readonly via: string;
  readonly at: number;
}

export function mintUserOrigin(via: string, at = Date.now()): UserOrigin {
  const o = Object.freeze({ kind: "user" as const, via, at });
  issued.add(o);
  return o;
}

export function assertUserOrigin(o: unknown): asserts o is UserOrigin {
  if (typeof o !== "object" || o === null || !issued.has(o)) {
    throw new Error("This action needs the user's own approval.");
  }
}
