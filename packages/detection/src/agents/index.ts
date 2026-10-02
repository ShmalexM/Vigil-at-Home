export { AGENT_CATALOG, VIGIL_CONNECTOR, VIGIL_SELF, type CatalogEntry } from './catalog.js';
export {
  AGENT_FIELD_PREFIXES,
  AI_EXCLUSION_DENY,
  isAgentField,
  conditionUsesAgentFields,
  conditionUsesFields,
  exclusionHidesAgent,
} from './fields.js';
export {
  compileAgentMatchers,
  argGlobMatch,
  type AgentProc,
  type CompiledAgentMatcher,
} from './match.js';
export { sessionId } from './session-id.js';
export { parsePsComm, mergePsArgs, MAX_PS_ARGS, type PsRow } from './ps-table.js';
export { AgentTracker, type SessionStart, type TrackerOptions } from './tracker.js';
export { AgentRegistry, type AgentRecord } from './registry.js';
export { toolRequestEvent, decide } from './preflight.js';
