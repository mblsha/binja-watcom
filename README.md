# Watcom DOS32 Platform (Binary Ninja Plugin)

This plugin registers a custom Binary Ninja platform for Watcom-style 32-bit DOS binaries and sets `regparm` as the default calling convention.

## Features

- Registers platform: `watcom-dos32-x86` (OS name: `watcom-dos`)
- Uses architecture: `x86`
- Ensures a `regparm` calling convention exists and makes it the platform default
- Adds platform recognizers for `Raw` and `Mapped` views
- Detects targets by checking:
  - `MZ` DOS header at offset `0x00`
  - New executable header pointer at `0x3C`
  - `LE` or `LX` signature at the pointed header

## Requirements

- Binary Ninja version `5000` or newer
- Python 3 plugin API

## Installation

1. Place this folder in your Binary Ninja plugins directory.
2. Restart Binary Ninja.

This repository already includes `plugin.json`, so it can also be packaged through the normal Binary Ninja plugin workflow.

## Behavior Notes

- Registration happens on import via `__init__.py`.
- Initialization is guarded and runs once per Binary Ninja session.
- If `x86` is unavailable, the plugin logs a warning and skips registration.

## Files

- `plugin.json`: Plugin metadata
- `__init__.py`: Import-time registration entrypoint
- `watcom_platform.py`: Platform + calling convention registration logic
