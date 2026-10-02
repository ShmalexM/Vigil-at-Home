import { describe, expect, it } from 'vitest';
import { isAppFrameUrl } from './app-frame.js';

const index = '/Applications/Vigil at Home.app/Contents/Resources/app.asar/out/renderer/index.html';
const indexUrl =
  'file:///Applications/Vigil%20at%20Home.app/Contents/Resources/app.asar/out/renderer/index.html';

describe('isAppFrameUrl', () => {
  it('accepts only the bundled page in a build, whatever its route', () => {
    expect(isAppFrameUrl(`${indexUrl}#home`, undefined, index)).toBe(true);
    expect(isAppFrameUrl(`${indexUrl}#popup/abc`, undefined, index)).toBe(true);
    expect(isAppFrameUrl('file:///Users/sam/Downloads/evil.html', undefined, index)).toBe(false);
    expect(isAppFrameUrl(`${indexUrl}.html`, undefined, index)).toBe(false);
    expect(isAppFrameUrl('https://example.com/', undefined, index)).toBe(false);
    expect(isAppFrameUrl('not a url', undefined, index)).toBe(false);
  });

  it('accepts the dev server origin in development', () => {
    const dev = 'http://localhost:5173';
    expect(isAppFrameUrl('http://localhost:5173/#home', dev, index)).toBe(true);
    expect(isAppFrameUrl('http://localhost:5174/#home', dev, index)).toBe(false);
    expect(isAppFrameUrl('http://localhost.evil.com:5173/', dev, index)).toBe(false);
  });
});
