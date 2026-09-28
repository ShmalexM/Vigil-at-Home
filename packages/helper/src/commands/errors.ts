export class ActionError extends Error {
  constructor(
    readonly code: 'invalid' | 'refused' | 'failed' | 'not_found',
    message: string,
  ) {
    super(message);
  }
}
