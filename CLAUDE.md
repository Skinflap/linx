# CLAUDE.md — Linx

Linux driver for the Lian Li 8.8" Universal LCD Screen. Reverse-engineered USB protocol with DES-CBC encryption. Image/video/LED control via CLI and GTK4 GUI.

## Stack

Python 3.11+ | pyusb | pycryptodome | Pillow | ffmpeg | PyGObject/GTK4/libadwaita
Dev: `pip install -e ".[dev]"` → ruff (lint) + pytest (`tests/`, hardware-free). CI in `.github/workflows/ci.yml`.

## Quick Start

```bash
cd ~/Projects/Linx
source .venv/bin/activate
linx matrix                # matrix screensaver
linx play video.mp4 -a     # video with ambilight
linx-gui                   # GTK4 control panel
```

## Architecture

- `src/linx/protocol.py` — USB constants, DES-CBC encryption, packet construction, `LED_COLORS` (single color source)
- `src/linx/device.py` — LCDDevice (bulk USB) + LEDDevice (HID); `diagnose()` USB-state classifier
- `src/linx/wake.py` — HID desktop-to-monitor mode switching
- `src/linx/content.py` — h264 encoding (NVENC/libx264), `encoded_h264()` temp-safe context mgr, matrix rain
- `src/linx/ambilight.py` — edge color sampling, decoder subprocess, LED sync thread
- `src/linx/config.py` — layered TOML config (correct escaping, preserves unknown sections)
- `src/linx/constants.py` — USB timeouts, polling intervals, buffer sizes (no scattered magic numbers)
- `src/linx/errors.py` — typed exceptions (`DeviceDisconnected`, `EncodeError`, …)
- `src/linx/log.py` — logging setup; `LINX_LOG=DEBUG` or CLI `--verbose` for debug output
- `src/linx/cli.py` — argparse CLI
- `src/linx/gui.py` — GTK4/Adwaita app shell
- `src/linx/widgets/` — status, display, led, service, viewport editor

## Conventions

- Library code logs via `log.get_logger(__name__)` — never `print()`. CLI result text uses `print` (stdout); errors go to the log (stderr).
- USB ops distinguish transient failure (return None) from a real disconnect (`raise DeviceDisconnected`). Don't swallow USBError silently — log it at minimum.
- Subprocesses get timeouts and guaranteed cleanup; temp files use `encoded_h264()` / try-finally.

## Design Principles

- **Lightweight 24/7 operation**: display pipeline must run forgotten in the background with no noticeable system impact
- **GUI is a remote control**: setting content persists after GUI closes. The display output is the product
- **Systemd service for persistent playback**: `linx.service` handles long-running display modes, GUI just configures

## Known Issues

- GUI (`gui.py` + `widgets/`) still couples widgets to `window.lcd`/`window.led` and blocks the UI thread on some device calls — a `DeviceController` decoupling + polish pass is planned.
- No GUI hotplug detection yet (manual Connect after replug).
- Hardware quirk: the LCD controller can fail USB enumeration and need a physical power-cycle — see `diagnose()` and the `project_linx_lcd_enum` note.
