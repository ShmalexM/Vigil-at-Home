import { describe, expect, it } from 'vitest';
import { defaultPaths } from '@vigil/helper';
import { helperSocketFor, NO_HELPER_SOCKET, userDataFor } from './test-isolation.js';

const REAL = defaultPaths().socket;

describe('helperSocketFor', () => {
  it('always uses the installed helper in a packaged app', () => {
    expect(helperSocketFor(true, {})).toBe(REAL);
    expect(helperSocketFor(true, { VIGIL_HELPER_SOCKET: '/tmp/x.sock', VIGIL_E2E: '1' })).toBe(
      REAL,
    );
  });

  it('uses an isolated helper when a development build is given one', () => {
    expect(helperSocketFor(false, { VIGIL_HELPER_SOCKET: '/tmp/x.sock', VIGIL_E2E: '1' })).toBe(
      '/tmp/x.sock',
    );
  });

  it('keeps an e2e run off the installed helper unless it opted in', () => {
    expect(helperSocketFor(false, { VIGIL_E2E: '1' })).toBe(NO_HELPER_SOCKET);
    expect(helperSocketFor(false, { VIGIL_E2E: '1', VIGIL_ALLOW_REAL_ENFORCEMENT: 'true' })).toBe(
      NO_HELPER_SOCKET,
    );
    expect(helperSocketFor(false, { VIGIL_E2E: '1', VIGIL_ALLOW_REAL_ENFORCEMENT: '1' })).toBe(
      REAL,
    );
  });

  it('leaves plain development runs as they were', () => {
    expect(helperSocketFor(false, {})).toBe(REAL);
  });
});

describe('userDataFor', () => {
  it('takes a throwaway profile in development builds only', () => {
    expect(userDataFor(false, { VIGIL_USER_DATA: '/tmp/p' })).toBe('/tmp/p');
    expect(userDataFor(false, {})).toBeUndefined();
    expect(userDataFor(true, { VIGIL_USER_DATA: '/tmp/p' })).toBeUndefined();
  });
});
