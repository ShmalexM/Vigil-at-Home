/**
 * Which computer the app runs on, for wording: Electron's user agent names
 * the OS. macOS is the default everywhere else.
 */
export const onLinux = typeof navigator !== 'undefined' && /\bLinux\b/.test(navigator.userAgent);

/** "Mac" on macOS, "computer" on Linux, as in "this Mac" / "this computer". */
export const computer = onLinux ? 'computer' : 'Mac';
