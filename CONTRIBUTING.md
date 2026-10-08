# Contributing

Thanks for helping. Issues and pull requests are welcome. Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md). Please report security problems privately, as [SECURITY.md](SECURITY.md) describes, not as issues.

## Pull requests

1. Fork the repo and branch from `main`.
2. Keep each PR to one change and fill in the template: what a user sees before and after, and how it works.
3. Run `pnpm check` before you push. CI runs the same checks, plus Mac tests on GitHub's macOS runners.
4. If you add code or assets you didn't write, credit them in `NOTICE` and `THIRD_PARTY_NOTICES.md`, and check that the license is compatible with Apache-2.0.

Two rules hold for every change. Detection is deterministic, so no AI output ever decides whether something is blocked. Only the user can allow or release something, so rules and the AI can contain or propose, never release.

New detection rules are especially welcome. Include a test with the malicious behaviour and a harmless look-alike, so the rule doesn't block normal work.

By contributing, you agree that your contribution is licensed under Apache-2.0, as section 5 of the [license](LICENSE) says.

## Layout

- TypeScript only. One pnpm workspace: apps in `apps/`, libraries in `packages/`.
- Packages are named `@vigil/<name>` and export TypeScript source directly (`"exports": { ".": "./src/index.ts" }`); the desktop app's bundler compiles them. Add a `typecheck` script to each package.
- Tests sit next to the code as `*.test.ts` and run with Vitest from the repo root.

## Shared types

`@vigil/core` is the contract between packages. Events, alerts, rules and actions are zod schemas with inferred types, so anything crossing a boundary (the helper socket, Santa sync, AI tool calls, the renderer) is validated with `Schema.parse`. Change the schema, not a local copy, and update the tests in `packages/core`.

The action policy in `packages/core/src/action.ts` is the single place that says who may do what. Every executor calls `authorizeAction` before acting.

## Naming

The product is **Vigil** (or **Vigil at Home**). `pnpm check:naming` fails the build if the former company name, or `dt-` style tokens derived from it, appear in any file or file name.

## Checks

`pnpm check` runs everything CI runs. Format with `pnpm format`.
