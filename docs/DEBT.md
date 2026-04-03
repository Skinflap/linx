# Linx — Technical Debt Inventory

Generated: 2026-04-03

---

## CRITICAL

### DEBT-001 — DES key/IV hardcoded in source
- **Location:** `src/linx/protocol.py:27`, `src/linx/protocol.py:71`
- **Category:** security / hardcoded
- **Severity:** critical
- **Description:** `DES_KEY = b'slv3tuzx'` is committed in plaintext. The key is also used as the IV. This is a known-bad encryption pattern (same key+IV makes identical plaintexts produce identical ciphertexts). The bigger issue is that if this ever needs to rotate, it's baked into the source rather than configurable.
- **Suggested fix:** Document that this key is public-by-design (device firmware uses it), add a comment making that explicit so future readers don't mistake it for a secret that needs protecting.

### DEBT-002 — `dist/linx.desktop` referenced in PKGBUILD but does not exist
- **Location:** `PKGBUILD:48`
- **Category:** other (packaging)
- **Severity:** critical
- **Description:** `install -Dm644 dist/linx.desktop` will hard-fail during `makepkg` because the file is not present in the repo. The package cannot be built from AUR as written.
- **Suggested fix:** Create `dist/linx.desktop` or remove the install line from PKGBUILD.

### DEBT-003 — `pyproject.toml` missing `ffmpeg` dependency
- **Location:** `pyproject.toml:13-17`
- **Category:** other (packaging)
- **Severity:** critical
- **Description:** `ffmpeg` is listed in PKGBUILD `depends` but not in `pyproject.toml` dependencies. A pip install will produce a broken install — `encode_h264`, `generate_matrix_h264`, `play_h264_with_ambilight` all shell out to `ffmpeg` and will silently fail at runtime with no helpful error.
- **Suggested fix:** Add a runtime check in the affected functions or document the system dependency clearly in both places (ffmpeg cannot be a Python dep, so a clear RuntimeError on missing binary is the right fix).

---

## HIGH

### DEBT-004 — No tests whatsoever
- **Location:** entire project
- **Category:** missing tests
- **Severity:** high
- **Description:** There is no `tests/` directory, no pytest config, no test files of any kind. Protocol packet construction, config merging, ambilight edge sampling, and the H.264 streaming state machine are all untested. The protocol layer in particular is the most critical to get right (wrong bytes brick the device).
- **Suggested fix:** Add at minimum unit tests for `make_header`, `des_encrypt`, `sample_edge_colors`, and `load_config`.

### DEBT-005 — `wake_from_desktop` swallows USB errors silently after claiming interface
- **Location:** `src/linx/wake.py:25-38`
- **Category:** missing error handling
- **Severity:** high
- **Description:** `hid.write()` failure is caught and passed silently. The function then polls for the TI MCU for 10 seconds. If the write failed (e.g. wrong endpoint, permissions issue), the caller gets `False` after a 10-second hang with no indication of why.
- **Suggested fix:** Distinguish write failure from device-not-found and surface the error to the caller.

### DEBT-006 — `_wait_buffer` has a 200-iteration hard limit with no failure signal
- **Location:** `src/linx/device.py:251-262`
- **Category:** missing error handling
- **Severity:** high
- **Description:** The polling loop runs at most 200 * 50ms = 10 seconds, then silently returns regardless of buffer state. Callers have no way to know the buffer was never ready. Streaming into a full buffer will cause device-side dropped frames or corruption with no logged indication.
- **Suggested fix:** Return a bool from `_wait_buffer` and log a warning when the deadline is hit.

### DEBT-007 — Temp H.264 files leaked on crash during encoding
- **Location:** `src/linx/content.py:17-33`, `src/linx/content.py:44-55`, `src/linx/content.py:68-96`
- **Category:** missing error handling
- **Severity:** high
- **Description:** `encode_h264` creates a `NamedTemporaryFile(delete=False)` and only unlinks it on success or ffmpeg error. If the caller crashes or is killed between encoding and playback, the file is left in `/tmp`. `generate_solid_h264` does the same with `check=True` but no cleanup on exception. `generate_matrix_h264` has the same pattern.
- **Suggested fix:** Use `contextlib.ExitStack` or `try/finally` to guarantee temp file cleanup regardless of exception path.

### DEBT-008 — `generate_matrix_h264` uses hardcoded font paths
- **Location:** `src/linx/content.py:80-85`
- **Category:** hardcoded
- **Severity:** high
- **Description:** Two Arch-specific font paths are tried (`/usr/share/fonts/noto/NotoSansMono-Regular.ttf`, `/usr/share/fonts/TTF/DejaVuSansMono.ttf`) and falls back to Pillow's bitmap default. On any system where neither path exists (e.g. a different Arch install without noto or dejavu), the matrix animation silently degrades to a pixelated default font with no warning.
- **Suggested fix:** Add a `font_path` config option and log a warning when falling back to the bitmap default.

### DEBT-009 — `LEDDevice.connect()` does not handle `set_configuration` failure
- **Location:** `src/linx/device.py:357`
- **Category:** missing error handling
- **Severity:** high
- **Description:** `self.dev.set_configuration()` is called without a try/except, unlike the identical call in `LCDDevice.connect()` (which wraps it). A USB error here will propagate uncaught and crash the caller.
- **Suggested fix:** Wrap in `try/except usb.core.USBError: pass` to match the LCD device pattern.

### DEBT-010 — `upload_file` does not validate target path or filename length
- **Location:** `src/linx/device.py:316-331`
- **Category:** missing error handling / security
- **Severity:** high
- **Description:** `target_path.encode('ascii')` will raise `UnicodeEncodeError` on non-ASCII paths with no useful error message. More critically, `fname_len` is written into the first 4 bytes of `header_data` but there is no guard if `fname_bytes` exceeds the 484 remaining bytes in the header buffer, which would silently truncate the filename.
- **Suggested fix:** Validate path is ASCII-safe and len(fname_bytes) <= 484 before proceeding, raising ValueError with a clear message on violation.

### DEBT-011 — `_do_color` in display widget imports from CLI module
- **Location:** `src/linx/widgets/display.py:336`
- **Category:** duplication / architecture
- **Severity:** high
- **Description:** `from ..cli import LED_COLORS` — the GUI imports a constant dict from the CLI module. `LED_COLORS` is defined in `cli.py` but is logically a protocol-level constant. This creates a circular dependency risk and means GUI and CLI silently diverge if one is updated (the GUI's `COLORS` dict and `cli.LED_COLORS` are already different: GUI has `Black`, CLI has `charcoal`).
- **Suggested fix:** Move both color dicts to `protocol.py` or a new `colors.py` constant module and import from there.

---

## MEDIUM

### DEBT-012 — `PKGBUILD` uses `sha256sums=('SKIP')`
- **Location:** `PKGBUILD:27`
- **Category:** security / other (packaging)
- **Severity:** medium
- **Description:** `SKIP` disables integrity verification for the git source. This is acceptable during development but must be replaced with actual checksums before AUR submission.
- **Suggested fix:** Pin a release tag and generate proper checksums before publishing.

### DEBT-013 — No type hints on any public functions or class methods
- **Location:** `src/linx/protocol.py`, `src/linx/device.py`, `src/linx/wake.py`, `src/linx/ambilight.py`, `src/linx/content.py`, `src/linx/config.py`
- **Category:** missing types
- **Severity:** medium
- **Description:** Every public function and class method in the library layer has no type annotations. Return types are ambiguous (several functions return `None | bytes | bool`), making IDE support and static analysis useless.
- **Suggested fix:** Add type hints to all public function signatures in the six source modules.

### DEBT-014 — Brightness slider in GUI hardcodes default `80` instead of reading config
- **Location:** `src/linx/widgets/display.py:39`
- **Category:** hardcoded
- **Severity:** medium
- **Description:** `self.brightness_scale.set_value(80)` ignores the loaded config. The config system sets a default of 80, and the user can override it, but the GUI never reads it — so a user who sets `brightness = 50` in their config will see the slider start at 80 every launch.
- **Suggested fix:** Pass the loaded config into `DisplayGroup.__init__` and set the initial slider value from it.

### DEBT-015 — Matrix duration/FPS in GUI hardcode defaults instead of reading config
- **Location:** `src/linx/widgets/display.py:77,80`
- **Category:** hardcoded
- **Severity:** medium
- **Description:** Same pattern as DEBT-014. `duration_row` defaults to 60, `fps_row` to 30, ignoring user config. The CLI correctly reads `config['matrix']['duration']`.
- **Suggested fix:** Same as DEBT-014 — pass config into the widget and apply configured defaults.

### DEBT-016 — Ambilight enabled state in GUI ignores config
- **Location:** `src/linx/widgets/led.py` (entire module)
- **Category:** hardcoded
- **Severity:** medium
- **Description:** The ambilight toggle and grayscale spinbox are always initialized to off/0. The config's `ambilight.enabled` and `ambilight.grayscale_max` are never read by the GUI.
- **Suggested fix:** Same as DEBT-014.

### DEBT-017 — `save_config` writes floats as nothing (missing type handling)
- **Location:** `src/linx/config.py:87-91`
- **Category:** other
- **Severity:** medium
- **Description:** `save_config` handles `bool`, `int`, and `str`, but not `float`. If any config value is a float (e.g. a user sets framerate to 29.97), `save_config` silently drops it — the `elif isinstance(val, int)` branch won't catch a float. No error is raised.
- **Suggested fix:** Add a `float` branch, or convert numeric types uniformly.

### DEBT-018 — `play_h264_with_ambilight` spawns `ffmpeg` without checking if it exists
- **Location:** `src/linx/ambilight.py:128-133`
- **Category:** missing error handling
- **Severity:** medium
- **Description:** `subprocess.Popen(['ffmpeg', ...])` will raise `FileNotFoundError` if ffmpeg is not on PATH. The exception propagates out of `decode_loop()` in the background thread and is only caught by the `except Exception` in `AmbilightThread.run()`, which will log it as an "LED error" — a very misleading message.
- **Suggested fix:** Check for ffmpeg existence at startup (or in `encode_h264`) and raise a clear error.

### DEBT-019 — `_send_and_read` timeout calculation uses `len(data) // 500`
- **Location:** `src/linx/device.py:111`
- **Category:** other
- **Severity:** medium
- **Description:** `write_ms = max(2000, len(data) // 500 + 2000)`. For the 202752-byte H.264 chunks, this computes to `202752 // 500 + 2000 = 2405ms`. At USB full-speed (12 Mbps), 200KB should take ~130ms; the formula is roughly right but the divisor appears empirically chosen with no documentation. If `h264_buf_len` changes (device returns a different size), this formula may produce a timeout that's too short.
- **Suggested fix:** Document the basis for the formula or compute timeout from actual USB bandwidth.

### DEBT-020 — `do_close_request` in GUI checks `self.lcd._stop is False` incorrectly
- **Location:** `src/linx/gui.py:73`
- **Category:** other
- **Severity:** medium
- **Description:** `self.lcd._stop is False` uses identity comparison (`is`) against a bool. This works in CPython (booleans are singletons) but is technically wrong style and will trigger linters. The intent is `not self.lcd._stop` or `self.lcd._stop == False`.
- **Suggested fix:** Change to `not self.lcd._stop`.

### DEBT-021 — `_flush_read` is an unbounded loop
- **Location:** `src/linx/device.py:95-101`
- **Category:** performance
- **Severity:** medium
- **Description:** The drain loop calls `dev.read()` with a 10ms timeout in a `while True`, breaking only on `USBTimeoutError`. If the device is in a pathological state and keeps producing data, this loops forever. In practice the 10ms timeout bounds each iteration, but the total drain time is unbounded.
- **Suggested fix:** Add a max-iteration guard (e.g. 20 reads) to prevent indefinite blocking.

---

## LOW

### DEBT-022 — `CMD_GET_TEMPERATURE`, `CMD_GET_PUMP_SPEED`, `CMD_SET_PUMP_SPEED` defined but unused
- **Location:** `src/linx/protocol.py:43-44`
- **Category:** dead code
- **Severity:** low
- **Description:** Three command constants are defined (`CMD_GET_TEMPERATURE = 96`, `CMD_SET_PUMP_SPEED = 97`, `CMD_GET_PUMP_SPEED = 98`) with no corresponding methods in `LCDDevice` or any other module. They're documented but inaccessible from the CLI or GUI.
- **Suggested fix:** Either implement the methods or add a comment that these are reserved for future implementation.

### DEBT-023 — `CMD_DEL_FILE`, `CMD_QUERY_DIR` defined but unused
- **Location:** `src/linx/protocol.py:41-42`
- **Category:** dead code
- **Severity:** low
- **Description:** `CMD_DEL_FILE = 42` and `CMD_QUERY_DIR = 99` are defined but no methods use them.
- **Suggested fix:** Same as DEBT-022.

### DEBT-024 — `CMD_START_PLAY1`, `CMD_START_PLAY2` imported but never called outside device.py internals
- **Location:** `src/linx/device.py:14-15`, `src/linx/cli.py:8`
- **Category:** dead code
- **Severity:** low
- **Description:** `CMD_START_PLAY1` and `CMD_START_PLAY2` are imported in `cli.py` but never used there. They're used in `device.py`'s `_wait_buffer` and `play_h264` via the `play_cmd` parameter, but `play_cmd` always defaults to `CMD_START_PLAY` and no caller ever passes a different value.
- **Suggested fix:** Remove the unused import from `cli.py`; either expose the multi-slot API or document it as reserved.

### DEBT-025 — `.gitignore` does not exclude `dist/*.whl` build artifacts
- **Location:** `.gitignore`
- **Category:** other
- **Severity:** low
- **Description:** `.gitignore` excludes `*.whl` at root level but PKGBUILD builds into `dist/`. If someone runs `python -m build` locally, the wheel lands in `dist/` not root. The `dist/` directory itself is not gitignored, so built wheels could be accidentally committed alongside the legitimate dist files.
- **Suggested fix:** Add `dist/*.whl` and `dist/*.tar.gz` to `.gitignore`.

### DEBT-026 — `linx.install` missing `post_upgrade` udevadm trigger call
- **Location:** `linx.install:9-11`
- **Category:** other
- **Severity:** low
- **Description:** `post_upgrade` runs `udevadm control --reload-rules` and `udevadm trigger` but does not echo a user-facing message like `post_install` does. Minor inconsistency — upgrades silently reload rules while installs notify the user to replug.
- **Suggested fix:** Add the same echo to `post_upgrade`.

### DEBT-027 — `pyproject.toml` has no `gui-dependencies` extra
- **Location:** `pyproject.toml`
- **Category:** other (packaging)
- **Severity:** low
- **Description:** GTK4/libadwaita deps are not Python packages and can't be listed in pyproject.toml, but `pygobject` can be. There is no `[project.optional-dependencies]` entry for GUI users. Someone doing `pip install linx` and then running `linx-gui` gets a confusing `ImportError: cannot import name 'gi'`.
- **Suggested fix:** Add `[project.optional-dependencies] gui = ["pygobject"]` so `pip install linx[gui]` works.

### DEBT-028 — `widgets/__init__.py` re-exports all four groups but nothing imports from it
- **Location:** `src/linx/widgets/__init__.py`
- **Category:** dead code
- **Severity:** low
- **Description:** `gui.py` imports directly from `widgets.status`, `widgets.display`, etc. The `__init__.py` re-exports are unused.
- **Suggested fix:** Either update `gui.py` to use `from .widgets import StatusGroup, ...` or remove the re-exports.

### DEBT-029 — `datetime` imported inside `sync_clock` instead of at module level
- **Location:** `src/linx/device.py:176`
- **Category:** other
- **Severity:** low
- **Description:** `import datetime` is inside the function body. This is a minor inefficiency (re-evaluated on each call) and inconsistent with the rest of the codebase which uses top-level imports.
- **Suggested fix:** Move `import datetime` to the top of `device.py`.

### DEBT-030 — `PIL` imported inside functions rather than at module top in several places
- **Location:** `src/linx/device.py:229`, `src/linx/content.py:65`, `src/linx/ambilight.py:115`, `src/linx/cli.py:167`
- **Category:** other
- **Severity:** low
- **Description:** `from PIL import Image` (and related) is deferred inside function bodies in multiple files. This is intentional in `cli.py` (avoids import at parse time) but in `device.py` and `content.py` there's no reason for it — Pillow is a hard dependency.
- **Suggested fix:** Move PIL imports to module level in `device.py` and `content.py`.

---

## Summary

| Severity | Count |
|---|---|
| Critical | 3 |
| High | 8 |
| Medium | 10 |
| Low | 9 |
| **Total** | **30** |

**Blocking for any release:** DEBT-002 (missing desktop file breaks makepkg), DEBT-003 (ffmpeg not declared as required).

**Most likely to cause user pain:** DEBT-005 (silent wake failure), DEBT-006 (silent buffer overflow), DEBT-007 (temp file leaks), DEBT-009 (LEDDevice crash on USB error).
