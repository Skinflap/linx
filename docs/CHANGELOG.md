# CHANGELOG — Linx

## 2026-04-08 — Mission 20260408-1943
- fix: ffmpeg ambilight decoder limited to 1 thread, uses stream_loop for looping (was 1074% CPU)
- fix: GUI close no longer stops display content or turns off LEDs
- fix: play thread joined on close so ffmpeg decoder is properly terminated
- fix: AmbilightThread switched from polling to event-driven wakeup
- docs: created docs/ scaffolding, STATE.md, session log
- docs: rewrote CLAUDE.md with architecture overview and design principles

## 2026-04-03 — v1.1
- feat: viewport editor with crop/rotate and live push
- feat: NVENC hardware encoding support with libx264 fallback
- feat: LED brightness slider
- feat: GUI state persistence across restarts

## 2026-04-03 — v1.0
- feat: full package rewrite from monolithic linx.py to src/linx/ with GTK4 GUI
- chore: CODEVOICE pass, security cleanup
