# STATE.md — Linx

Last updated: 2026-06-11 (modernization pass)

## What Works

- **Full package structure**: `src/linx/` with protocol, device, wake, content, ambilight, config, cli, gui, widgets
- **CLI**: 10 subcommands (test, version, image, play, color, matrix, brightness, stop, wake, led, upload)
- **GUI**: GTK4/Adwaita with status, display, LED, service widgets. Viewport crop/rotate editor with live push
- **USB protocol**: DES-CBC encrypted bulk transfers to LCD (1CBE:A088), raw HID to LED ring (0416:8050), wake from desktop mode (1A86:AD21)
- **H.264 streaming**: chunked transfer with flow control, NVENC hardware encoding when available, libx264 fallback
- **Ambilight**: edge-color sampling from video frames, drives 60-LED RGB ring via separate HID device
- **Config**: layered TOML — /etc/linx.conf → ~/.config/linx/config.toml → CLI flag
- **State persistence**: GUI saves/restores mode, paths, rotation, brightness
- **PKGBUILD**: v1.0.0, builds from git source

## What Was Fixed (this session)

- **ffmpeg CPU explosion**: decoder subprocess now uses `-threads 1` and `-stream_loop -1` instead of rapid process restarts. Was consuming 1074% CPU on a 120x480@10fps stream
- **GUI independence**: closing the GUI no longer stops display content or turns off LEDs. Device keeps showing whatever was last displayed
- **Process lifecycle**: play thread is joined on GUI close so ffmpeg decoder is properly terminated. No orphan processes
- **Idle efficiency**: AmbilightThread switched from 100ms polling to Event-based wakeup (1 wakeup/sec idle vs 10/sec)

## Modernization Pass (2026-06)

Backend overhauled on branch `enhance/modernization`:

- **Fixed**: dist/ now complete (udev/service/conf/desktop + new `linx.svg` icon); pytest suite (`tests/`, 32 tests) + ruff + CI; version single-sourced from `__init__.__version__` (dynamic in pyproject), all at 1.1.0.
- **Fixed**: logging (`log.py`) replaces `print()` in library code; magic numbers hoisted to `constants.py`; typed exceptions in `errors.py`.
- **Fixed**: USB errors no longer swallowed silently — transient vs `DeviceDisconnected`; `connect()` fails gracefully on busy/permission; `play_h264` stops instead of spinning on disconnect; `threading.Event` stop flag; validated h264 buffer size.
- **Fixed**: subprocess/temp-file leaks — `encoded_h264()` context manager, ffmpeg timeouts + guaranteed kill (no orphans), matrix stderr→DEVNULL (no pipe deadlock).
- **Fixed**: config — correct TOML string escaping, warns (not silent) on parse error, preserves unknown sections, deep-copies defaults (was corrupting module state).
- **Fixed**: dead `generate_solid_h264` removed; color table de-duped (protocol → content); unverified pump/temp CMDs labeled.

## Still Open (frontend — planned)

- GUI still couples widgets to `window.lcd`/`window.led` and blocks the UI thread on some device calls → `DeviceController` decoupling + non-blocking calls planned.
- Missing modern Adwaita chrome: primary menu, About, Preferences, keyboard shortcuts.
- No GUI hotplug detection (manual Connect after replug).
- Viewport crop/rotation not persisted; `restore_state` reaches into viewport internals + uses a magic 500ms delay.
- Duplicate color table still in `widgets/display.py` (COLORS) — fold into protocol.
- CLAUDE.md still untracked in git.
