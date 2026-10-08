import { join } from 'node:path';
import {
  app,
  BrowserWindow,
  Menu,
  nativeTheme,
  screen,
  session,
  shell,
  Tray,
  type Rectangle,
} from 'electron';
import trayIcon from '../../resources/trayTemplate.png?asset';
import trayAlertIcon from '../../resources/trayAlertTemplate.png?asset';
import trayLinuxIcon from '../../resources/trayLinux.png?asset';
import trayLinuxAlertIcon from '../../resources/trayLinuxAlert.png?asset';
import type { Pushes, ThemePref } from '../shared/ipc.js';
import { DEFAULT_APPEARANCE, windowBackground, type AppearanceSettings } from '../shared/themes.js';
import { isAppFrameUrl } from './app-frame.js';
import { scaledSize, textScale } from './text-scale.js';

// macOS tints template images to fit the menu bar; Linux shows them as drawn,
// and its panels are mostly dark, so it gets white ones.
const TRAY =
  process.platform === 'darwin'
    ? { idle: trayIcon, alert: trayAlertIcon }
    : { idle: trayLinuxIcon, alert: trayLinuxAlertIcon };

const POPOVER = { width: 380, height: 540 };
const POPUP = { width: 420, height: 400 };
/**
 * Each window's page is a renderer process (30 to 80 MB on macOS). The main
 * window's goes when it closes and a hidden popup's after a minute, so an
 * idle menu-bar app holds little. The popover is the exception: it is loaded at start-up and kept,
 * because a cold open measured 1 to 2 seconds on CI Macs and a warm one
 * 10 to 60 ms (docs/performance.md).
 */
const RELEASE_POPUP_MS = 60 * 1000;
/** How long the first popup waits for its first paint before showing anyway. */
const POPUP_SHOW_FALLBACK_MS = 1500;

/** Where renderer pages are served from, for loading and for checking IPC senders. */
const INDEX_HTML = join(import.meta.dirname, '../renderer/index.html');

/** True for a frame showing Vigil's own page; see isAppFrameUrl. */
export function isAppFrame(url: string): boolean {
  return isAppFrameUrl(url, process.env['ELECTRON_RENDERER_URL'], INDEX_HTML);
}

function secure(win: BrowserWindow): BrowserWindow {
  // Never navigate away from the app or open new windows inside it.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) void shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  return win;
}

function load(win: BrowserWindow, route: string): void {
  const dev = process.env['ELECTRON_RENDERER_URL'];
  if (dev) void win.loadURL(`${dev}#${route}`);
  else void win.loadFile(INDEX_HTML, { hash: route });
}

const webPreferences = () => ({
  preload: join(import.meta.dirname, '../preload/index.cjs'),
  contextIsolation: true,
  sandbox: true,
  nodeIntegration: false,
  spellcheck: false,
  // No inspector in a release build.
  devTools: !app.isPackaged,
});

/** The only web permission the app's pages use: copy buttons (navigator.clipboard.writeText). */
const ALLOWED_PERMISSIONS = new Set(['clipboard-sanitized-write']);

/** Deny every other web permission and embedded <webview>s. Call before any window opens. */
export function restrictWebContents(): void {
  session.defaultSession.setPermissionRequestHandler((_wc, permission, callback) =>
    callback(ALLOWED_PERMISSIONS.has(permission)),
  );
  session.defaultSession.setPermissionCheckHandler((_wc, permission) =>
    ALLOWED_PERMISSIONS.has(permission),
  );
  app.on('web-contents-created', (_e, contents) => {
    contents.on('will-attach-webview', (e) => e.preventDefault());
  });
}

/**
 * The app's three surfaces:
 * - the menu-bar item and its popover ("Needs you"),
 * - the main window,
 * - the always-on-top detection popup.
 */
export class Windows {
  private tray?: Tray;
  private popover?: BrowserWindow;
  private main?: BrowserWindow;
  private popup?: BrowserWindow;
  private appearance: AppearanceSettings = DEFAULT_APPEARANCE;
  private readonly releaseTimers = new Map<BrowserWindow, ReturnType<typeof setTimeout>>();

  createTray(): void {
    this.tray = new Tray(TRAY.idle);
    this.tray.setToolTip('Vigil at Home');
    this.tray.on('click', () => this.togglePopover());
    this.tray.on('right-click', () => this.togglePopover());
    // Linux tray hosts (GNOME's AppIndicator extension, KDE) often open a
    // menu instead of passing on the click, so give them one.
    if (process.platform === 'linux') {
      this.tray.setContextMenu(
        Menu.buildFromTemplate([
          { label: 'What needs you', click: () => this.togglePopover() },
          { label: 'Open Vigil at Home', click: () => this.openMain() },
        ]),
      );
    }
  }

  /** Menu-bar icon: count of alerts waiting on the user, alert glyph when any. */
  setNeedsYou(count: number): void {
    if (!this.tray) return;
    this.tray.setImage(count > 0 ? TRAY.alert : TRAY.idle);
    if (process.platform === 'darwin') this.tray.setTitle(count > 0 ? ` ${count}` : '');
    this.tray.setToolTip(count > 0 ? `Vigil at Home: ${count} need you` : 'Vigil at Home');
  }

  togglePopover(): void {
    if (this.popover?.isVisible()) {
      this.popover.hide();
      return;
    }
    this.popover = this.loadPopover();
    const size = this.popoverSize();
    const pos = popoverPosition(this.tray?.getBounds(), size.width);
    this.popover.setBounds({ ...pos, ...size }, false);
    this.popover.show();
    this.popover.focus();
  }

  /** Load the popover without showing it, so the first click opens it at once. */
  prewarmPopover(): void {
    this.popover = this.loadPopover();
  }

  private loadPopover(): BrowserWindow {
    if (!this.popover || this.popover.isDestroyed()) {
      this.popover = secure(
        new BrowserWindow({
          ...POPOVER,
          show: false,
          frame: false,
          resizable: false,
          movable: false,
          fullscreenable: false,
          skipTaskbar: true,
          alwaysOnTop: true,
          transparent: process.platform === 'darwin',
          vibrancy: 'popover',
          backgroundColor: process.platform === 'darwin' ? '#00000000' : '#141414',
          webPreferences: webPreferences(),
        }),
      );
      this.popover.on('blur', () => this.popover?.hide());
      this.followTextSize(this.popover);
      load(this.popover, 'popover');
    }
    return this.popover;
  }

  openMain(route = 'home'): void {
    this.popover?.hide();
    if (this.main && !this.main.isDestroyed()) {
      this.send(this.main, 'navigate', route);
      this.main.show();
      this.main.focus();
      return;
    }
    this.main = secure(
      new BrowserWindow({
        width: 1180,
        height: 760,
        minWidth: 900,
        minHeight: 600,
        show: false,
        title: 'Vigil at Home',
        ...(process.platform === 'darwin'
          ? { titleBarStyle: 'hiddenInset' as const, trafficLightPosition: { x: 16, y: 18 } }
          : {}),
        backgroundColor: this.background(),
        webPreferences: webPreferences(),
      }),
    );
    this.main.once('ready-to-show', () => this.main?.show());
    // A Dock icon only while the main window is open.
    void app.dock?.show();
    this.main.on('closed', () => app.dock?.hide());
    load(this.main, route);
  }

  /**
   * Show the detection popup without taking keyboard focus from what the user
   * is typing. It floats above full-screen apps and every Space, because
   * Focus modes can hide ordinary notifications.
   */
  showPopup(alertId: string): void {
    if (!this.popup || this.popup.isDestroyed()) {
      this.popup = secure(
        new BrowserWindow({
          ...POPUP,
          show: false,
          frame: false,
          resizable: false,
          minimizable: false,
          maximizable: false,
          fullscreenable: false,
          skipTaskbar: true,
          // The card draws its own shadow. A native shadow on a transparent
          // window keeps the old outline after fitPopup resizes it on macOS.
          hasShadow: false,
          transparent: true,
          backgroundColor: '#00000000',
          ...(process.platform === 'darwin' ? { type: 'panel' } : {}),
          webPreferences: webPreferences(),
        }),
      );
      this.releaseWhenHidden(this.popup, RELEASE_POPUP_MS);
      this.popup.setAlwaysOnTop(true, 'screen-saver');
      this.popup.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
      this.followTextSize(this.popup);
      load(this.popup, `popup/${alertId}`);
      // A hidden transparent panel may never paint, so on macOS 'ready-to-show'
      // can fail to fire and the first popup would stay hidden. Show it on
      // whichever comes first: first paint, the page finishing loading, or a
      // short fallback.
      const win = this.popup;
      let shown = false;
      const showOnce = () => {
        if (shown || win.isDestroyed() || win !== this.popup) return;
        shown = true;
        this.placeAndShowPopup();
      };
      win.once('ready-to-show', showOnce);
      win.webContents.once('did-finish-load', showOnce);
      setTimeout(showOnce, POPUP_SHOW_FALLBACK_MS);
      return;
    }
    this.send(this.popup, 'popup', alertId);
    this.placeAndShowPopup();
  }

  private placeAndShowPopup(): void {
    if (!this.popup) return;
    const display = screen.getDisplayNearestPoint(screen.getCursorScreenPoint());
    const wa = display.workArea;
    const { width } = scaledSize(POPUP, this.scale(), wa);
    this.popup.setPosition(wa.x + wa.width - width - 12, wa.y + 12, false);
    this.popup.showInactive();
  }

  /**
   * Resize the popup to its content, keeping it pinned to the top-right corner.
   * `height` is in page pixels, so it grows with the text size.
   */
  fitPopup(height: number): void {
    if (!this.popup || this.popup.isDestroyed()) return;
    const wa = screen.getDisplayMatching(this.popup.getBounds()).workArea;
    const { width } = scaledSize(POPUP, this.scale(), wa);
    const h = Math.min(Math.round(height * this.scale()), wa.height - 24);
    this.popup.setBounds({ x: wa.x + wa.width - width - 12, y: wa.y + 12, width, height: h });
  }

  private scale(): number {
    return textScale(this.appearance.uiFontSize);
  }

  private popoverSize(): { width: number; height: number } {
    const wa = screen.getDisplayNearestPoint(screen.getCursorScreenPoint()).workArea;
    return scaledSize(POPOVER, this.scale(), wa);
  }

  /**
   * The popover and popup draw larger with the Appearance text size (up to
   * 200%) by zooming the page; the main window scales its own page.
   */
  private followTextSize(win: BrowserWindow): void {
    win.webContents.on('did-finish-load', () => {
      if (!win.isDestroyed()) win.webContents.setZoomFactor(this.scale());
    });
  }

  hidePopup(): void {
    this.popup?.hide();
  }

  /** Close `win` once it has been hidden for `ms`; showing it again cancels that. */
  private releaseWhenHidden(win: BrowserWindow, ms: number): void {
    const cancel = () => {
      clearTimeout(this.releaseTimers.get(win));
      this.releaseTimers.delete(win);
    };
    win.on('show', cancel);
    win.on('closed', cancel);
    win.on('hide', () => {
      cancel();
      const timer = setTimeout(() => win.isDestroyed() || win.isVisible() || win.close(), ms);
      timer.unref();
      this.releaseTimers.set(win, timer);
    });
  }

  /** Close the popup now if hidden (what its timer does after a while). */
  releaseHidden(): void {
    for (const win of [this.popup]) if (win && !win.isDestroyed() && !win.isVisible()) win.close();
  }

  broadcast<K extends keyof Pushes>(channel: K, ...args: Pushes[K]): void {
    for (const win of BrowserWindow.getAllWindows()) this.send(win, channel, ...args);
  }

  applyTheme(pref: ThemePref, appearance: AppearanceSettings = DEFAULT_APPEARANCE): void {
    nativeTheme.themeSource = pref;
    this.appearance = appearance;
    for (const win of [this.popover, this.popup]) {
      if (win && !win.isDestroyed()) win.webContents.setZoomFactor(this.scale());
    }
    if (this.popover && !this.popover.isDestroyed()) {
      const { x, y } = this.popover.getBounds();
      this.popover.setBounds({ x, y, ...this.popoverSize() }, false);
    }
    this.broadcast('theme', pref);
  }

  /** The theme's window colour, so the main window doesn't flash before it paints. */
  private background(): string {
    return windowBackground(this.appearance, nativeTheme.shouldUseDarkColors ? 'dark' : 'light');
  }

  private send<K extends keyof Pushes>(win: BrowserWindow, channel: K, ...args: Pushes[K]): void {
    if (!win.isDestroyed()) win.webContents.send(`vigil:${channel}`, ...args);
  }
}

function popoverPosition(
  tray: Rectangle | undefined,
  width = POPOVER.width,
): { x: number; y: number } {
  const anchor = tray && tray.width > 0 ? tray : undefined;
  const display = anchor
    ? screen.getDisplayMatching(anchor)
    : screen.getDisplayNearestPoint(screen.getCursorScreenPoint());
  const wa = display.workArea;
  const x = anchor
    ? Math.round(anchor.x + anchor.width / 2 - width / 2)
    : wa.x + wa.width - width - 12;
  const y = anchor ? anchor.y + anchor.height + 4 : wa.y + 4;
  return {
    x: Math.min(Math.max(x, wa.x + 4), wa.x + wa.width - width - 4),
    y,
  };
}
