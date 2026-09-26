import { contextBridge, ipcRenderer } from 'electron';
import { CALL_NAMES, PUSH_NAMES } from '../shared/channels.js';
import type { Pushes, VigilApi } from '../shared/ipc.js';

const api = Object.fromEntries(
  CALL_NAMES.map((name) => [
    name,
    (...args: unknown[]) => ipcRenderer.invoke(`vigil:${name}`, ...args),
  ]),
) as Omit<VigilApi, 'on'>;

const on: VigilApi['on'] = (channel, fn) => {
  if (!(PUSH_NAMES as readonly string[]).includes(channel))
    throw new Error(`Unknown channel ${channel}`);
  const listener = (_e: Electron.IpcRendererEvent, ...args: unknown[]) =>
    (fn as (...a: unknown[]) => void)(...(args as Pushes[typeof channel]));
  ipcRenderer.on(`vigil:${channel}`, listener);
  return () => ipcRenderer.removeListener(`vigil:${channel}`, listener);
};

contextBridge.exposeInMainWorld('vigil', { ...api, on } satisfies VigilApi);
