# STATE.md — Linx

Last updated: 2026-04-08 (mission 20260408-1943)

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

## What's Broken / Missing

- **dist/ directory**: PKGBUILD references `dist/linx.udev`, `dist/linx.service`, `dist/linx.conf.default`, `dist/linx.desktop` — none exist. Package build fails for anyone who clones
- **No tests**: zero test files in project. Protocol, color parsing, edge sampling are all testable pure functions
- **Version drift**: `__init__` says 1.1.0, pyproject.toml and PKGBUILD say 1.0.0
- **CLAUDE.md untracked**: exists in working tree but not in git
- **12 uncommitted files**: CODEVOICE delimiter reformatting (no logic changes), ready to commit

## Known Debt

- Duplicate color tables in protocol.py, content.py, display.py
- Hardcoded magic numbers in protocol packet construction
- Silent config parse error swallowing
- `generate_solid_h264` is dead code (imported but never called from CLI)
- `CMD_GET_TEMPERATURE`, `CMD_SET_PUMP_SPEED`, `CMD_GET_PUMP_SPEED` defined but unimplemented
- Viewport crop state not persisted in saved GUI state
- `restore_state` accesses viewport internals directly
