# Linx — State

**As of:** 2026-04-03
**Health:** Degraded

---

## What Works

**Core driver logic — fully functional (imports clean, logic verified):**
- `protocol.py` — DES-CBC encryption, packet construction, all USB command constants
- `device.py` — `LCDDevice` and `LEDDevice` USB controllers, full command set
- `wake.py` — mode switching from desktop (WCH HID) to monitor (TI MCU)
- `ambilight.py` — edge-color sampling, `AmbilightThread`, video ambilight pipeline
- `content.py` — ffmpeg H.264 encoding, solid color generation, matrix rain generation, PNG generation
- `config.py` — TOML config loading, system+user merge, defaults
- `cli.py` — full argparse CLI: test, version, image, play, color, matrix, brightness, stop, wake, led, upload
- `gui.py` + all four `widgets/` modules — GTK4+libadwaita GUI, all panels implemented

**Venv state:** `.venv` exists, installed editable (`__editable__.linx-1.0.0.pth`). Packages present:
- pyusb 1.3.1
- pycryptodome 3.23.0
- Pillow 12.2.0
- linx 1.0.0 (editable)

**Runtime deps available on system:**
- ffmpeg n8.1 (`/usr/bin/ffmpeg`)
- python-gobject (system), libadwaita 1.8.4 (GTK4+Adw available in venv via system)
- Python 3.14.3

**Packaging artifacts (dist/):**
- `linx.udev` — udev rules for all 3 USB devices, uses TAG+="uaccess" (no root needed)
- `linx.service` — systemd user service, runs `linx matrix` on login
- `linx.conf.default` — full default TOML config
- `linx.desktop` — desktop entry calling `linx-gui`

---

## What's Broken

**1. Git state is completely wrong.**
The single remote commit (`f3a071d "Add files via upload"`) tracks the OLD monolithic `linx.py` (1184-line single file). Everything in `src/`, `dist/`, `pyproject.toml`, `PKGBUILD`, `assets/`, `linx.install` is untracked. The current working tree is a ground-up rewrite that has never been committed.

Working tree vs HEAD diff: HEAD has `Linx/linx.py` (old), current tree has `src/linx/` package (new). All new code shows as untracked.

**2. PKGBUILD cannot build — `python-build` and `python-installer` not installed system-wide.**
- `python-build` — not in pacman, not installed
- `python-installer` — not in pacman, not installed
- `makepkg -si` would fail at the build phase

Runtime deps `python-pyusb` and `python-pycryptodome` also not installed system-wide (only in `.venv`). If installed via PKGBUILD, the AUR packages for these would need to be present.

**3. `egg-info/SOURCES.txt` is stale — missing `widgets/` subpackage.**
The `.egg-info` was generated before `src/linx/widgets/` was added. `find_packages()` does discover `linx.widgets` correctly, so a fresh wheel build would include it. Stale egg-info is cosmetic — editable install still works.

**4. `SOURCES.txt` omission means `linx-gui` entry point may not be properly registered in a wheel build.**
`pyproject.toml` declares `linx-gui = "linx.gui:main"` but `gui.py` and `widgets/` are not in SOURCES.txt. A wheel built from the current egg-info might omit the GUI. Regenerating egg-info would fix this.

**5. No tests exist.**
Zero test files in the project. No pytest, no test directory. The only test files found are pycryptodome's own self-tests inside `.venv/`. Runtime behavior can only be verified against hardware.

---

## In Progress

Nothing explicitly marked in-progress in the code. The project appears structurally complete as a rewrite but is **unpersisted** — the entire new codebase exists only on disk, never committed.

The `.gitignore` file is untracked too, implying the repo scaffolding for the new layout was set up locally but never pushed.

There's a note about a broken "clear the screen" feature referenced in Mitchell's memory (`feedback_linx_screen_clear.md`): H.264 clear mechanism is noted as unsolved. Looking at the code, `clear_layers()` in `device.py` sends two PNG pushes (transparent + black) but does NOT send a `CMD_STOP_PLAY` first — this may be the unsolved piece.

---

## Recent Changes

Only one remote commit exists (`f3a071d`, Feb 20 2026): the old monolithic `Linx/linx.py`.

The entire current codebase — the Python package restructure into `src/linx/`, the GUI, the widgets, the PKGBUILD — is uncommitted work created after that commit and never pushed to GitHub.

Git log shows two additional commits that exist only locally:
- `b977a25 Initial commit — Linx`
- `8a1ed39 Pre-wipe commit: add CLAUDE.md`

These appear to be orphaned or on a different branch root. The working tree is fully diverged from origin.

---

## Test Health

No test suite. No tests at all. Pass rate: N/A.

Hardware-dependent functionality (USB commands, LED ring, H.264 streaming) cannot be unit tested without the physical device. No mocking layer exists.

---

## Environment

| Item | Value |
|---|---|
| Python | 3.14.3 |
| Venv | `/home/skinflap/Projects/Linx/.venv` (Python 3.14.3) |
| Editable install | Yes (`__editable__.linx-1.0.0.pth`) |
| pyusb | 1.3.1 (venv only) |
| pycryptodome | 3.23.0 (venv only) |
| Pillow | 12.2.0 (venv only) |
| ffmpeg | n8.1 (system, `/usr/bin/ffmpeg`) |
| python-gobject | System install, accessible from venv |
| libadwaita | 1:1.8.4-1 (system) |
| python-build | NOT INSTALLED (blocks PKGBUILD) |
| python-installer | NOT INSTALLED (blocks PKGBUILD) |
| python-pyusb (system) | NOT INSTALLED (blocks PKGBUILD runtime) |
| python-pycryptodome (system) | NOT INSTALLED (blocks PKGBUILD runtime) |

**To unblock a new instance:**
1. `cd /home/skinflap/Projects/Linx && source .venv/bin/activate` — all Python deps present
2. `git add` everything and commit — current tree is entirely untracked
3. `sudo pacman -S python-build python-installer` before attempting PKGBUILD
4. AUR: `python-pyusb`, `python-pycryptodome` needed for PKGBUILD runtime deps
