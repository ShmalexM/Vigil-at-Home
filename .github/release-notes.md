Download the DMG for your Mac:

- **Apple silicon** (M1 and later): `Vigil-at-Home-<version>-arm64.dmg`
- **Intel**: `Vigil-at-Home-<version>-x64.dmg`

Not sure which you have? Apple menu > About This Mac: "Chip: Apple M..." means Apple silicon, "Processor: Intel" means Intel.

## Install

1. Open the DMG and drag **Vigil at Home** into **Applications**.
2. Open it from Applications. macOS says it can't check the app for malicious software, because releases aren't signed with an Apple Developer ID yet. Choose **Done**.
3. Open **System Settings > Privacy & Security**, scroll to Security, and choose **Open Anyway** next to Vigil at Home. Confirm with your password.
4. Vigil appears as a shield in the menu bar. It has no Dock icon until you open its window.

You only do steps 2 and 3 once. Building from source skips them; see the README.

## What works in this build

See the README's status section. Until the sensors and the Vigil helper are installed, blocks are simulated and labelled that way in the app.
