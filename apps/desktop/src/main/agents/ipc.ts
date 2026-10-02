import type { Handlers } from '../ipc.js';
import type { AgentService } from './service.js';

type AgentCall =
  | 'listAgents'
  | 'listAgentNames'
  | 'getAgent'
  | 'saveAgent'
  | 'setAgentWatch'
  | 'setAgentStatus'
  | 'removeAgent'
  | 'resetAgent'
  | 'previewAgentMatch'
  | 'listAgentCandidates'
  | 'listAgentSessions'
  | 'getAgentSession'
  | 'getAgentPrefs'
  | 'setAgentPrefs'
  | 'getPreflightStatus'
  | 'getAgentToolsStatus'
  | 'listVigilHelpers';

/**
 * The Agents page. Every change here is the user's own click, so the service
 * mints a UserOrigin for it; nothing an agent sends over the socket comes
 * through these handlers.
 */
export function agentsHandlers(agents: AgentService): Pick<Handlers, AgentCall> {
  return {
    listAgents: () => agents.listAgents(),
    listAgentNames: () => agents.listAgentNames(),
    getAgent: (id) => agents.getAgent(id),
    saveAgent: (input) => agents.saveAgent(input),
    setAgentWatch: (id, on) => agents.setAgentWatch(id, on),
    setAgentStatus: (id, status) => agents.setAgentStatus(id, status),
    removeAgent: (id) => agents.removeAgent(id),
    resetAgent: (id) => agents.resetAgent(id),
    previewAgentMatch: (match) => agents.previewAgentMatch(match),
    listAgentCandidates: () => agents.listAgentCandidates(),
    listAgentSessions: (id, page) => agents.listAgentSessions(id, page?.before),
    getAgentSession: (id) => agents.getAgentSession(id),
    getAgentPrefs: () => agents.prefs(),
    setAgentPrefs: (patch) => agents.setPrefs(patch),
    getPreflightStatus: () => agents.preflightStatus(),
    getAgentToolsStatus: () => agents.toolsStatus(),
    listVigilHelpers: () => agents.listVigilHelpers(),
  };
}
