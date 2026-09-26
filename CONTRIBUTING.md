# Contributing

## Layout

- TypeScript only. One pnpm workspace: apps in `apps/`, libraries in `packages/`.
- Packages are named `@vigil/<name>` and export TypeScript source directly (`"exports": { ".": "./src/index.ts" }`); the desktop app's bundler compiles them. Add a `typecheck` script to each package.
- Tests sit next to the code as `*.test.ts` and run with Vitest from the repo root.

## Shared types

`@vigil/core` is the contract between packages. Events, alerts, rules and actions are zod schemas with inferred types, so anything crossing a boundary (the helper socket, Santa sync, AI tool calls, the renderer) is validated with `Schema.parse`. Change the schema, not a local copy, and update the tests in `packages/core`.

The action policy in `packages/core/src/action.ts` is the single place that says who may do what. Every executor calls `authorizeAction` before acting.

## Naming

The product is **Vigil** (or **Vigil at Home**). `pnpm check:naming` fails the build if the former company name, or `dt-` style tokens derived from it, appear in any file or file name. When porting code from upstream Vigil, rename those leftovers.

## Checks

`pnpm check` runs everything CI runs. Format with `pnpm format`.
