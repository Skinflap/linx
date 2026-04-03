# Linx

Linux driver for the **Lian Li 8.8" Universal Screen** -- the LCD + LED ring combo found in Lian Li cases (e.g. Lancool III).

Reverse-engineered from L-Connect 3's `lianli.lcd207.dll`. No Windows required.

## Hardware

| Component | USB ID | Description |
| - | - | - |
| LCD (monitor mode) | `1cbe:a088` | TI MCU -- all display commands |
| LCD (desktop mode) | `1a86:ad21` | WCH HID -- standby, wake only |
| LED ring | `0416:8050` | 60 RGB LEDs, 3 groups of 20 |

The LCD has two mutually exclusive USB modes. In **monitor mode** (TI MCU), it accepts display commands. In **desktop mode** (WCH HID), it's in standby -- use `linx wake` to switch it back.

Display resolution: **480x1920** (portrait). The device firmware handles orientation.

## Install

### Arch Linux (PKGBUILD)

```
makepkg -si
```

This installs the `linx` command, udev rules (no root needed), and a systemd user service.

### Manual

```
sudo pacman -S python-pyusb python-pycryptodome python-pillow ffmpeg
pip install -e .
sudo cp dist/linx.udev /usr/lib/udev/rules.d/70-linx.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

Unplug and replug the screen after installing udev rules.

## Usage

```
# Test connection
linx test

# Display an image (any format Pillow supports)
linx image photo.png
linx image wallpaper.jpg

# Play a video (any format ffmpeg supports, loops by default)
linx play video.mp4
linx play clip.gif
linx play animation.mp4 --no-loop

# Solid color
linx color red
linx color cyan

# Matrix rain screensaver
linx matrix
linx matrix --duration 120 --fps 24

# Adjust brightness (0-100)
linx brightness 75

# Stop video playback
linx stop

# LED ring control
linx led red
linx led 255,128,0    # custom RGB
linx led off

# Wake from desktop/standby mode
linx wake

# Show firmware version
linx version

# Upload file to device (e.g. custom boot logo)
linx upload boot.jpg /usr/data/boot.jpg
```

Press **Ctrl+C** to stop video playback or the matrix screensaver.

### Systemd service

Run Linx as a background service that starts on login:

```
systemctl --user enable --now linx      # start + auto-start on login
systemctl --user stop linx              # stop
systemctl --user restart linx           # restart
journalctl --user -u linx -f            # view logs
```

The default service runs the matrix screensaver. Override via drop-in:

```
systemctl --user edit linx
```

Then set:

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/linx play /path/to/video.mp4
```

### Ambilight (LED edge-matching)

Add `-a` to sync the LED ring to whatever's on screen -- samples edge pixels and drives the 60 LEDs to match:

```
linx matrix -a           # green glow while matrix runs
linx play video.mp4 -a   # LEDs follow the video
linx image photo.png -a  # LEDs match image edges
```

### Configuration

Optional config files (TOML):
- System: `/etc/linx.conf`
- User: `~/.config/linx/config.toml`

```toml
[display]
brightness = 80

[matrix]
duration = 60
fps = 30

[ambilight]
enabled = false
grayscale_max = 0
```

CLI args override config values. Use `--config /path/to/file.toml` for an explicit config.

## How It Works

The LCD uses DES-CBC encrypted USB bulk transfers (key = IV = `slv3tuzx`). Each command is a 512-byte packet: 500-byte plaintext command buffer, encrypted, padded to 512 bytes with a `[0xA1, 0x1A]` trailer.

**Display layers:**

- **JPG layer** (cmd 101): opaque background
- **PNG layer** (cmd 102): transparent overlay composited on top
- **H.264 video** (cmd 121): replaces background; PNG overlay still composites on top

On Linux, the JPEG push command is unreliable for files >2KB, so PNG is used for all image operations.

**H.264 streaming** sends raw H.264 data in ~200KB chunks, each prefixed with an encrypted header. The device has a 3-block buffer with flow control -- the driver polls `QueryBlock` when the buffer is full.

## Python API

```python
from linx import LCDDevice, LEDDevice, WIDTH, HEIGHT

# LCD
lcd = LCDDevice()
lcd.connect()
lcd.init()
lcd.set_brightness(80)
lcd.prepare_display()
lcd.push_png(png_bytes)
lcd.play_h264('video.h264')
lcd.stop_play()
lcd.close()

# LED ring
led = LEDDevice()
led.connect()
led.set_all(255, 0, 0)
led.set_leds([(r,g,b)] * 60)
led.off()
led.close()
```

## Known Issues

- **JPEG push broken on Linux**: The device never responds to JPEG (cmd 101) for files larger than ~2KB under libusb. PNG (cmd 102) works at all sizes. The driver uses PNG for everything.

- **uaccess requires local session**: The udev rules use the `uaccess` tag, which requires systemd-logind and a local login session. Won't work over pure SSH. Fall back to `sudo linx` in that case.

## License

Unlicense. Do whatever you want with it.
