export * from './types.js';
export { lintRule, isAnchored, type LintResult, type LintOptions } from './rules/lint.js';
export { globProblem, globToRegExp, regexProblem, renderTemplate } from './rules/compile.js';
export { KNOWN_FIELDS, COMPUTED_FIELDS } from './rules/fields.js';
export {
  DetectionEngine,
  compileRule,
  RuleCompileError,
  type CheckOptions,
  type EngineConfig,
} from './engine.js';
export {
  SafetyFloor,
  DEFAULT_PROTECTED_PATH_GLOBS,
  DEFAULT_NEVER_BLOCK_NETWORKS,
  type SafetyConfig,
} from './safety.js';
export {
  Feedback,
  DEFAULT_DEMOTION,
  USER_BLOCKED_HASHES,
  assertExceptionScope,
  type DemotionPolicy,
  type DecisionResult,
} from './feedback.js';
export type { UserOrigin } from './origin.js';
export * from './state/stores.js';
export {
  sqliteStores,
  migrate,
  DETECTION_MIGRATIONS,
  type SqlDatabase,
  type SqlStatement,
  type RuleRepository,
  type SqliteDetectionStores,
} from './state/sqlite.js';
export { macosCoreRules, CREDENTIAL_STORE_GLOBS } from './packs/macos-core.js';
export { linuxCoreRules } from './packs/linux-core.js';
export {
  agentWatchRules,
  SECRET_PATH_RES,
  SECRET_FILE_GLOBS,
  UPLOAD_RES,
  PIPE_SINK_RE,
  COPY_OUT_RES,
  PASTE_HOST_RE,
  ENV_DUMP_RE,
  PERSIST_RES,
  TAMPER_RES_NOCASE,
  TAMPER_RE_CASED,
  KEYCHAIN_SECRET_RE,
  AGENT_CONFIG_RE,
  CONFIG_WRITE_RE,
  CONFIG_INPLACE_RE,
  SCRIPT_WRITE_RE,
  MCP_ADD_RE,
  PREFLIGHT_PIPE_RE,
  PREFLIGHT_PROCSUB_RE,
  AGENT_CONFIG_GLOBS,
} from './packs/agent-watch.js';
export {
  agentPreflightRules,
  PREFLIGHT_PROBING_RULE_ID,
  PREFLIGHT_SOCKET_RULE_ID,
  PREFLIGHT_SOCKET_TOOL,
  builtinRules,
  builtinRulesFor,
} from './packs/agent-preflight.js';
export {
  replayRule,
  type ReplayReport,
  type ReplayOptions,
  type ReplayContext,
} from './proposals/replay.js';
export { proveChange, type ImpactReport, type ProveInput } from './proposals/prover.js';
export {
  RulePipeline,
  MemoryProposalStore,
  ProposeRuleInput,
  ProposeTuningInput,
  ProposeRetirementInput,
  type Proposal,
  type ProposalStatus,
  type ProposalStore,
  type SubmitResult,
  type PipelineOptions,
} from './proposals/pipeline.js';
export {
  summarizeTelemetry,
  redactPath,
  redactCommandLine,
  type FlaggedEvent,
  type TelemetrySummary,
} from './proposals/telemetry.js';
export {
  RuleReviewer,
  MemoryReviewStateStore,
  type ReviewOutcome,
  type ReviewState,
  type ReviewStateStore,
  type RuleReviewerOptions,
} from './proposals/reviewer.js';
export {
  detectionReadTools,
  ruleLanguageGuide,
  RuleReviewOutput,
  submitReview,
  runRuleReview,
  type AnalyzeRunner,
  type DetectionToolContext,
  type ReadToolLike,
  type ReviewSubmission,
} from './proposals/tools.js';
export { RULE_REVIEW_PROMPT } from './proposals/prompt.js';
export { mergeRules } from './merge.js';
export * from './feeds/index.js';
export * from './agents/index.js';
export {
  RuleEditor,
  exclusionFor,
  type EditResult,
  type ExcludeScope,
  type PreviewResult,
  type RuleEditView,
} from './editing.js';
