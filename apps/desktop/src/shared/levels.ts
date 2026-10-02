/**
 * How Good, Fair and Poor are worked out, in the words the app shows. The
 * level is about protection only; what needs the user's decision is counted
 * separately as Needs you. The logic is computeStatus in main/status.ts; keep
 * the two in step.
 */
export const LEVEL_RULES = {
  poor: 'A protection layer that is installed has stopped.',
  fair: 'A protection layer is not installed or not working fully.',
  good: 'Every protection layer is running. Alerts don’t change this; anything waiting on you is shown as Needs you.',
} as const;
