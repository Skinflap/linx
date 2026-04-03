# Linx — INTERFACES.md
**Last updated:** 2026-04-03
**Verified by:** kru-analyst-interface (direct code reading)

---

## Internal Interfaces

### Module Dependency Graph

```
cli.py ──────────────────────────────────┐
  └── device.py (LCDDevice, LEDDevice)   │
  └── wake.py (wake_from_desktop)        │
  └── ambilight.py (3 exports)           │
  └── content.py (4 exports)             │
  └── config.py (load_config)            │
                                         │
gui.py ──────────────────────────────────┤
  └── widgets/status.py (StatusGroup)    │
  └── widgets/display.py (DisplayGroup)  │
      └── content.py                     │
      └── ambilight.py                   │
      └── cli.py (LED_COLORS) ←-- cross-import warning
  └── widgets/led.py (LEDGroup)          │
  └── widgets/service.py (ServiceGroup)  │
                                         │
device.py ───────────────────────────────┤
  └── protocol.py (constants + make_header)
  └── wake.py                            │
                                         │
wake.py ─────────────────────────────────┤
  └── protocol.py                        │
                                         │
content.py ──────────────────────────────┤
  └── protocol.py (WIDTH, HEIGHT)        │
                                         │
ambilight.py ────────────────────────────┘
  └── protocol.py (WIDTH, HEIGHT, inside function body)
```

---

### protocol.py — Constants and Packet Builder

No imports from other linx modules. Foundation layer.

**Exports:**
```python
LCD_VID, LCD_PID = 0x1CBE, 0xA088   # TI MCU (monitor mode)
HID_VID, HID_PID = 0x1A86, 0xAD21   # WCH HID (desktop mode)
LED_VID, LED_PID = 0x0416, 0x8050   # LED ring controller
WIDTH = 480
HEIGHT = 1920
DES_KEY = b'slv3tuzx'
MONITOR_MODE_CMD: bytes              # b'5f3759df' as ASCII bytes (8 bytes)

# Command IDs
CMD_GET_VER        = 10
CMD_REBOOT         = 11
CMD_ROTATE         = 13
CMD_BRIGHTNESS     = 14
CMD_SET_FRAMERATE  = 15
CMD_GET_H264_BLOCK = 17
CMD_UPDATE_FIRMWARE = 40
CMD_DEL_FILE       = 42
CMD_SET_CLOCK      = 51
CMD_STOP_CLOCK     = 52
CMD_GET_TEMPERATURE = 96
CMD_SET_PUMP_SPEED = 97
CMD_GET_PUMP_SPEED = 98
CMD_QUERY_DIR      = 99
CMD_PUSH_JPG       = 101  # BROKEN on Linux for files >2KB
CMD_PUSH_PNG       = 102
CMD_START_PLAY1    = 119
CMD_START_PLAY2    = 120
CMD_START_PLAY     = 121
CMD_QUERY_BLOCK    = 122
CMD_STOP_PLAY      = 123
CMD_SWITCH_DESKTOP = 150

def des_encrypt(data: bytes | bytearray) -> bytes: ...
def make_header(cmd: int, data_at_8: bytes | None = None) -> bytes: ...
# Returns 512-byte encrypted command packet
```

---

### device.py — LCDDevice and LEDDevice

#### LCDDevice

```python
class LCDDevice:
    dev: usb.core.Device | None
    h264_buf_len: int              # device-reported buffer size, default 202752
    _stop: bool                    # thread-safe stop signal (no lock, CPython GIL only)

    def connect(self) -> bool      # finds 1cbe:a088, auto-wakes from HID mode
    def close(self) -> None
    def send_cmd(self, cmd: int, data: bytes | None = None) -> bytes | None
    def send_with_payload(self, cmd: int, payload: bytes,
                          data_at_8: bytes | None = None) -> bytes | None
    def init(self) -> None                        # SetFrameRate(30)
    def get_version(self) -> str | None           # ASCII, bytes 8-40 of response
    def set_brightness(self, level: int) -> bytes | None   # clamps 0-100
    def set_rotation(self, rot: int) -> bytes | None       # 0-3
    def set_framerate(self, fps: int) -> bytes | None      # clamps 1-99
    def stop_play(self) -> bytes | None
    def sync_clock(self, mode: int = 2) -> bytes | None    # 0=off,1=on,2=sync
    def stop_clock(self) -> bytes | None
    def query_block(self) -> bytes | None
    def check_h264_block(self) -> int             # queries device, updates h264_buf_len
    def push_image(self, image_bytes: bytes,
                   cmd: int = CMD_PUSH_PNG) -> bytes | None
    def push_png(self, png_bytes: bytes) -> bytes | None
    def clear_layers(self) -> None                # clears PNG overlay + JPG background
    def prepare_display(self) -> None             # sync_clock + stop_clock + clear_layers
    def request_stop(self) -> None                # sets _stop = True (GUI thread use)
    def play_h264(self, filepath: str, loop: bool = True,
                  play_cmd: int = CMD_START_PLAY,
                  play_count: int = 1) -> bool
    def upload_file(self, data: bytes,
                    target_path: str) -> bytes | None   # path must be ASCII
```

#### LEDDevice

```python
class LEDDevice:
    NUM_LEDS = 60
    LEDS_PER_GROUP = 20
    dev: usb.core.Device | None

    def connect(self) -> bool
    def close(self) -> None
    def get_version(self) -> str | None          # format: "{maj}_{min}"
    def set_leds(self, leds_rgb: list[tuple[int, int, int]]) -> None
    # leds_rgb: up to 60 (r, g, b) tuples; fire-and-forget (no response)
    def set_all(self, r: int, g: int, b: int) -> None
    def off(self) -> None                         # set_all(0, 0, 0)
```

---

### wake.py

```python
def wake_from_desktop() -> bool
# Sends MONITOR_MODE_CMD to 1a86:ad21 interface 1, endpoint 0x02
# Polls for 1cbe:a088 (20 × 500ms = 10s max)
# Returns True if TI MCU enumerated
```

---

### content.py

```python
def encode_h264(input_path: str, width: int = 480,
                height: int = 1920) -> str | None
# Returns temp .h264 file path, or None on ffmpeg error
# Caller must os.unlink() the returned path

def generate_solid_h264(color: str = 'red', width: int = 480, height: int = 1920,
                         duration: int = 5, fps: int = 30) -> str
# color: named key from colors dict, or hex string (e.g. '0xFF8800')
# Returns temp .h264 file path, caller must os.unlink()

def generate_matrix_h264(width: int = 480, height: int = 1920,
                          duration: int = 30, fps: int = 30,
                          ambilight: AmbilightThread | None = None) -> str
# If ambilight provided, calls ambilight.update_frame(img.copy()) every 3 frames
# Returns temp .h264 file path, caller must os.unlink()

def make_png(width: int = 480, height: int = 1920,
             color: tuple[int, int, int] = (255, 0, 0)) -> bytes
# Returns PNG image as bytes (in-memory, no file)
```

---

### ambilight.py

```python
def sample_edge_colors(img: PIL.Image.Image,
                        num_leds: int = 60) -> list[tuple[int, int, int]]
# Returns list of num_leds (r, g, b) tuples
# Walk order: bottom(L→R), right(B→T), top(R→L), left(T→B)
# Each sample averages an 8×8 pixel block

class AmbilightThread(threading.Thread):
    def __init__(self, led_device: LEDDevice, grayscale_max: int = 0): ...
    def update_frame(self, img: PIL.Image.Image) -> None   # thread-safe (Lock)
    def stop(self) -> None                                  # sets self.running = False
    # Runs at 10 Hz; skips frames where img reference unchanged

def play_h264_with_ambilight(
    lcd: LCDDevice,
    led: LEDDevice,
    filepath: str,
    loop: bool = True,
    ambi: AmbilightThread | None = None,
    grayscale_max: int = 0,
) -> None
# Spawns decoder subprocess (ffmpeg, quarter-res, 10fps) in daemon thread
# Runs lcd.play_h264() on calling thread (blocking)
# Cleans up decoder and calls led.off() on exit if own_ambi
```

---

### config.py

```python
SYSTEM_CONFIG = Path('/etc/linx.conf')
USER_CONFIG = Path('~/.config/linx/config.toml')  # expanded at runtime

def load_config(path: str | None = None) -> dict
# Priority: explicit path > USER_CONFIG > SYSTEM_CONFIG > DEFAULTS
# Missing files silently skipped
# Returns full config dict with all sections and keys

def save_config(config: dict, path: str | None = None) -> None
# Writes only non-default values to USER_CONFIG (or explicit path)
# Creates parent dirs automatically
# NOTE: no caller currently exists in the codebase (dead export)
```

**DEFAULTS:**
```python
{
    'display':   {'brightness': 80, 'rotation': 0},
    'matrix':    {'duration': 60, 'fps': 30},
    'ambilight': {'enabled': False, 'grayscale_max': 0},
    'service':   {'mode': 'matrix', 'file': '', 'color': 'red'},
}
```

---

### gui.py — Window and App

```python
class LinxWindow(Adw.ApplicationWindow):
    lcd: LCDDevice | None       # shared state, set by StatusGroup
    led: LEDDevice | None       # shared state, set by StatusGroup

    def on_connection_changed(self) -> None
    # Called by StatusGroup after connect/disconnect
    # Propagates sensitivity to DisplayGroup and LEDGroup

    def show_toast(self, message: str) -> None
    # Safe to call from any thread via GLib.idle_add

    def do_close_request(self) -> bool   # returns False (allow close)

class LinxApp(Adw.Application):
    # app-id: 'dev.linx.controller'

def main() -> None
```

---

### widgets/ — GTK Widget Groups

All widget groups share the pattern: `__init__(self, window: LinxWindow)`.

#### StatusGroup (widgets/status.py)

Manages connect/disconnect lifecycle. Sets `window.lcd` and `window.led` via GLib.idle_add callback after background thread completes.

Connection sequence (background thread):
1. `LCDDevice()` → `.connect()` → `.get_version()`
2. `LEDDevice()` → `.connect()` → `.get_version()`
3. `GLib.idle_add(_connect_done, lcd, led, fw, led_ver)`

#### DisplayGroup (widgets/display.py)

Modes: `['Image', 'Video', 'Color', 'Matrix']` (indices 0-3).

Cross-widget access: reads `window.led_group.ambilight_row.get_active()` and `window.led_group.grayscale_row.get_value()` from `_get_ambilight_state()`.

Imports `LED_COLORS` from `cli.py` inside `_do_color()`.

```python
def set_sensitive_all(self, sensitive: bool) -> None
```

#### LEDGroup (widgets/led.py)

Color picker via `Gtk.ColorDialogButton`. Reads RGBA and converts to `(int, int, int)` via `_get_rgb()`.

```python
def set_sensitive_all(self, sensitive: bool) -> None
```

Ambilight state exposed via:
- `ambilight_row: Adw.SwitchRow` — `.get_active()` returns `bool`
- `grayscale_row: Adw.SpinRow` — `.get_value()` returns `float` (cast to `int`)

#### ServiceGroup (widgets/service.py)

Wraps `systemctl --user` calls:
```python
def _systemctl(*args) -> tuple[int, str]   # (returncode, stdout.strip())
```

Commands used: `is-active linx.service`, `is-enabled linx.service`, `start/stop/restart/enable/disable linx.service`.

---

## USB Protocol Interface

### Devices

| Device | VID:PID | Mode | Interface |
|---|---|---|---|
| LCD (monitor) | 1cbe:a088 | Bulk transfer | Interface 0, ep 0x01 (OUT), ep 0x81 (IN) |
| LCD (desktop/HID) | 1a86:ad21 | Interrupt | Interface 1, ep 0x02 (OUT) |
| LED ring | 0416:8050 | HID interrupt | Interface 0, ep 0x01 (OUT), ep 0x81 (IN) |

### LCD Packet Format

512-byte encrypted packet for every command:
```
Plaintext buffer (500 bytes):
  [0]     cmd (uint8)
  [1]     0x00
  [2]     0x1A
  [3]     0x6D
  [4:8]   timestamp (uint32 LE, ms since process start)
  [8:n]   command-specific data (optional)
  [n:500] zero-padded

Encrypted with DES-CBC:
  key = iv = b'slv3tuzx'
  PKCS7-padded to 504 bytes

Final packet (512 bytes):
  [0:504]  encrypted payload
  [504:510] zeros
  [510]    0xA1
  [511]    0x1A
```

### H.264 Streaming Packet

Header (512 bytes, encrypted) + raw H.264 chunk:
```
data_at_8[0:4]  chunk_len (uint32 big-endian)
data_at_8[4]    0x00
data_at_8[5]    play_count (uint8)
```

Flow control: poll `CMD_QUERY_BLOCK`, check `response[buf_idx]` (8=slot0, 9=slot1, 10=slot2). Wait if `> 3`. Chunk size: `h264_buf_len` (default ~198KB). Delay: 30ms per chunk.

### Image Push Packet

Header (512 bytes) + raw image data:
```
data_at_8[0:4]  image_len (uint32 big-endian)
```

### LED Protocol (64-byte HID)

Set LEDs (3 packets per call, fire-and-forget):
```
pkt[0] = 17                           # command ID
pkt[1] = group * 20                   # LED offset: 0, 20, or 40
pkt[2:4] = 0x00 0x00
pkt[4:64] = RGB data                  # 20 LEDs × 3 bytes (R, G, B)
```

Get version: `pkt[0] = 16` → response `pkt[1]._pkt[2]` as version string.

### Wake Protocol

512-byte packet to HID ep 0x02:
```
pkt[0:8] = b'5f3759df'   # MONITOR_MODE_CMD
pkt[8:]  = zeros
```

---

## CLI Interface

### Entry Points

| Command | Entrypoint |
|---|---|
| `linx` | `linx.cli:main` |
| `linx-gui` | `linx.gui:main` |

### Subcommands

| Subcommand | Positional Args | Flags | Effect |
|---|---|---|---|
| `test` | — | — | Init device, print firmware + buffer info |
| `version` | — | — | Print firmware version |
| `image` | `file` | `-a/--ambilight` | Push resized image as PNG |
| `play` | `file` | `--no-loop`, `-a/--ambilight`, `-g/--grayscale INT` | Stream video (encode if not .h264) |
| `color` | `color` | `-a/--ambilight` | Generate + stream solid color H.264 (loops) |
| `matrix` | — | `-a/--ambilight`, `--duration INT`, `--fps INT` | Generate + stream matrix animation (loops) |
| `brightness` | `level` (0-100) | — | Set brightness |
| `stop` | — | — | Stop playback |
| `wake` | — | — | Switch device from HID to monitor mode |
| `led` | `color` (name or R,G,B) | — | Set LED ring color |
| `upload` | `file`, `target` | — | Upload file to device filesystem |

**Global:** `--config/-c FILE` — TOML config override.

**Exit codes:** 0 = success, 1 = error (device not found, invalid args, encode failure).

---

## Config Interface

| File | Format | Priority |
|---|---|---|
| `/etc/linx.conf` | TOML | Lowest |
| `~/.config/linx/config.toml` | TOML | Middle |
| `--config FILE` | TOML | Highest |

### Full Schema

```toml
[display]
brightness = 80        # int 0-100 (default 80)
rotation = 0           # int 0-3 (default 0) -- NOT used by CLI

[matrix]
duration = 60          # int seconds (default 60)
fps = 30               # int (default 30)

[ambilight]
enabled = false        # bool (default false)
grayscale_max = 0      # int 0-255 (default 0; 0 = full color)

[service]
mode = "matrix"        # str: "matrix"|"play"|"image"|"color"
file = ""              # str path (for play/image modes)
color = "red"          # str color name (for color mode)
```

---

## External Interfaces

### ffmpeg

Required on `$PATH`. No version constraint documented.

| Use | Mode | Input | Output |
|---|---|---|---|
| `encode_h264` | subprocess.run | any video/image file | raw H.264 file |
| `generate_solid_h264` | subprocess.run | lavfi color source | raw H.264 file |
| `generate_matrix_h264` | subprocess.Popen (stdin) | RGB24 raw frames | raw H.264 file |
| `play_h264_with_ambilight` decoder | subprocess.Popen (stdout) | raw H.264 file | RGB24 raw frames at 120×480, 10fps |

Encoding parameters: `libx264`, `bframes=0`, `ultrafast` preset, `yuv420p`, 4 threads.

### pyusb (>=1.2)

USB device access. Exceptions handled: `usb.core.USBError`, `usb.core.USBTimeoutError`. Write timeout scales with data size (`max(2000, len(data) // 500 + 2000)` ms). Read timeout: 2000ms (LCD), 500ms (LED).

### Pillow (>=10.0)

Image open/resize/convert/save. Font paths tried (in order): `/usr/share/fonts/noto/NotoSansMono-Regular.ttf`, `/usr/share/fonts/TTF/DejaVuSansMono.ttf`, `load_default()`.

### pycryptodome (>=3.19)

`Crypto.Cipher.DES`, `DES.MODE_CBC`.

### GTK4 + libadwaita (gui only)

`gi.require_version('Gtk', '4.0')`, `gi.require_version('Adw', '1')`. Not in pyproject.toml dependencies (system package).

### systemd (gui only)

`systemctl --user` via subprocess. Timeout: 10s per call.

---

## systemd Interface

**Service:** `linx.service` (user scope)
- Default: `ExecStart=/usr/bin/linx matrix`
- Stop: `ExecStart=/usr/bin/linx stop`
- Restart: on-failure, 5s delay
- After: `graphical-session.target`

**udev:** `70-linx.rules` — `uaccess` tag on all three USB devices. Requires systemd-logind and local session.

---

## Undocumented / Problematic Interfaces

| Item | Location | Issue |
|---|---|---|
| `display.py` imports `LED_COLORS` from `cli.py` | `widgets/display.py:337` | Widget imports from entry-point module — cross-import smell |
| `LCDDevice._stop` (plain bool) | `device.py:33` | No lock; thread-safety relies on CPython GIL only |
| `config.display.rotation` | `config.py`, `linx.conf.default` | Documented in config, never read by CLI |
| `save_config()` | `config.py:70` | Exported, no callers in codebase |
| `CMD_START_PLAY1/2` slots | `device.py`, `protocol.py` | Defined, `play_h264` accepts them, no CLI exposure |
| `set_rotation()` on LCDDevice | `device.py:163` | No CLI subcommand |
