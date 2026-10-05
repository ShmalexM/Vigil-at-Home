import type { Handlers } from '../ipc.js';
import type { Connectors } from './connectors.js';
import type { PackService } from './service.js';

type PackCall =
  | 'getPack'
  | 'setPackMode'
  | 'setPackVoice'
  | 'sayToLead'
  | 'clearLeadChat'
  | 'decideLeadAction'
  | 'decidePackTool'
  | 'adoptDog'
  | 'updateDog'
  | 'retireDog'
  | 'runDog'
  | 'setPackToolChoice'
  | 'addConnector'
  | 'setConnectorEnabled'
  | 'removeConnector'
  | 'refreshConnector'
  | 'listPackNotes'
  | 'clearPackNotes';

/**
 * The Pack page. Every call here is the user's own click or message; what
 * the Lead dog asks for comes back through the service, never through these
 * handlers.
 */
export function packHandlers(pack: PackService, connectors: Connectors): Pick<Handlers, PackCall> {
  const result = async (work: () => Promise<unknown> | unknown) => {
    try {
      await work();
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  };
  return {
    getPack: () => pack.view(),
    setPackMode: (mode) => pack.setMode(mode),
    setPackVoice: (voice) => pack.setVoice(voice),
    // The answer arrives as a push; the call returns once the Lead dog has replied.
    sayToLead: (text, context) => result(() => pack.say(text, context)),
    clearLeadChat: () => pack.clearChat(),
    decideLeadAction: (messageId, actionId, approve) =>
      pack.decideAction(messageId, actionId, approve),
    decidePackTool: (id, decision) => pack.decideTool(id, decision),
    adoptDog: (input) => result(() => pack.adopt(input)),
    updateDog: (id, patch) => pack.updateDog(id, patch),
    retireDog: (id) => pack.retire(id),
    runDog: (id) => result(() => pack.runDog(id)),
    setPackToolChoice: (key, choice) => pack.setToolChoice(key, choice),
    addConnector: (input) =>
      result(async () => {
        const c = connectors.add(input);
        await pack.refreshConnector(c.id).catch(() => undefined);
      }),
    setConnectorEnabled: (id, on) => connectors.setEnabled(id, on),
    removeConnector: (id) => connectors.remove(id),
    refreshConnector: (id) => result(() => pack.refreshConnector(id)),
    listPackNotes: (filter) => pack.notes(filter),
    clearPackNotes: (dog) => pack.clearNotes(dog),
  };
}
