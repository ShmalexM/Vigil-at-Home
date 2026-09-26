import type { VigilApi } from '../shared/ipc';

declare global {
  interface Window {
    vigil: VigilApi;
  }
}
