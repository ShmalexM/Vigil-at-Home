// Renders the PNG icons in resources/ from their SVG sources:
//   icon.svg              -> icon.png (1024 px; electron-builder makes the .icns from it)
//   tray*Template.svg     -> tray*Template.png (18 px) and tray*Template@2x.png (36 px)
//   trayLinux*.svg        -> trayLinux*.png (22 px) and trayLinux*@2x.png (44 px)
// Run it after editing any of those SVGs and commit the PNGs with them.
//
// Usage: node scripts/render-icons.mjs
//   Set CHROMIUM_PATH to a Chrome or Chromium binary if playwright-core has none
//   of its own, e.g. "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const resources = join(dirname(fileURLToPath(import.meta.url)), '..', 'resources');

const jobs = [
  ['icon.svg', 'icon.png', 1024],
  ['trayTemplate.svg', 'trayTemplate.png', 18],
  ['trayTemplate.svg', 'trayTemplate@2x.png', 36],
  ['trayAlertTemplate.svg', 'trayAlertTemplate.png', 18],
  ['trayAlertTemplate.svg', 'trayAlertTemplate@2x.png', 36],
  ['trayLinux.svg', 'trayLinux.png', 22],
  ['trayLinux.svg', 'trayLinux@2x.png', 44],
  ['trayLinuxAlert.svg', 'trayLinuxAlert.png', 22],
  ['trayLinuxAlert.svg', 'trayLinuxAlert@2x.png', 44],
];

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined });
try {
  const page = await browser.newPage();
  for (const [source, out, size] of jobs) {
    await page.setViewportSize({ width: size, height: size });
    const svg = readFileSync(join(resources, source), 'utf8');
    await page.setContent(
      `<style>html,body{margin:0;background:transparent}svg{display:block;width:${size}px;height:${size}px}</style>${svg}`,
    );
    await page.screenshot({ path: join(resources, out), omitBackground: true });
    console.log(`${out}  ${size} px`);
  }
} finally {
  await browser.close();
}
