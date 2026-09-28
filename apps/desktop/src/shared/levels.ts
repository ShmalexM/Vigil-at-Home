/**
 * How Good, Fair and Poor are worked out, in the words the app shows. The
 * logic is computeStatus in main/status.ts; keep the two in step.
 */
export const LEVEL_RULES = {
  poor: 'A high or critical alert isn’t contained yet, or a protection layer that is installed has stopped.',
  fair: 'An alert is waiting for your decision, or a protection layer is not installed or not working fully.',
  good: 'None of the above. Everything is running and nothing needs you.',
} as const;

/** What each level asks of the user, in a few words. */
export const LEVEL_MEANING = {
  good: 'Nothing needs you',
  fair: 'Needs a look',
  poor: 'Needs you now',
} as const;
