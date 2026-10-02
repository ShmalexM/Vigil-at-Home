import { resolve } from 'node:path';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'electron-vite';

// Everything the app imports is a devDependency and gets bundled, so the packaged
// app ships only `out/` and no node_modules. A package that must stay external
// (for example one that spawns its own binary) goes in `dependencies` and needs
// externalizeDepsPlugin here.

export default defineConfig({
  main: {},
  preload: {
    build: {
      rollupOptions: {
        // electron-vite 5 does not externalize electron for a CommonJS preload under
        // vite 8, which bundles the npm stub and leaves window.vigil undefined.
        external: ['electron'],
        output: { format: 'cjs', entryFileNames: '[name].cjs' },
      },
    },
  },
  renderer: {
    root: resolve(import.meta.dirname, 'src/renderer'),
    plugins: [react()],
    build: { rollupOptions: { input: resolve(import.meta.dirname, 'src/renderer/index.html') } },
  },
});
