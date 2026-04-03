# linx

linux driver for the **lian li 8.8" universal screen** — the lcd + led ring in lancool III and similar cases.

reverse-engineered from L-Connect 3's `lianli.lcd207.dll`. no windows required.

## hardware

| component | usb id | what it does |
| - | - | - |
| lcd (monitor mode) | `1cbe:a088` | TI MCU — display commands |
| lcd (desktop mode) | `1a86:ad21` | WCH HID — standby, wake only |
| led ring | `0416:8050` | 60 rgb leds, 3 groups of 20 |

two mutually exclusive usb modes. **monitor mode** takes display commands. **desktop mode** is standby — `linx wake` switches it back.

display: **480x1920** portrait. pixel (0,0) at top-left.

## install

### arch (pkgbuild)

```
makepkg -si
```

installs `linx` cli, `linx-gui`, udev rules (no root needed), and a systemd user service.

### manual

```
sudo pacman -S python-pyusb python-pycryptodome python-pillow ffmpeg
pip install -e .
pip install -e '.[gui]'   # optional — needs python-gobject + libadwaita
sudo cp dist/linx.udev /usr/lib/udev/rules.d/70-linx.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

unplug and replug after installing udev rules.

## gui

```
linx-gui
```

gtk4 + libadwaita control panel. connect, pick content, adjust, push to device.

- **viewport editor** — drag a crop box over your image/video. scroll to resize. rotate the source with the arrow buttons until your content is oriented how you want it. cyan edge = physical screen top.
- **live sync** — toggle the Live button and the device updates as you drag the crop box around. wysiwyg.
- **led brightness** — slider controls led ring brightness for both manual color and ambilight.
- **ambilight** — toggle it on, leds sample the screen edges and match. pixel-exact.
- **state persistence** — mode, file paths, rotation, brightness all saved on close and restored on relaunch.

## cli

```
linx test                      # connection test + firmware info
linx image photo.png           # display an image (any pillow format)
linx play video.mp4            # play video (any ffmpeg format, loops)
linx play clip.gif --no-loop   # play once
linx color red                 # solid color (just pushes a jpeg, instant)
linx color 0xFF8800            # hex works too
linx matrix                    # matrix rain screensaver
linx matrix --duration 120     # longer matrix
linx brightness 75             # display brightness 0-100
linx stop                      # stop playback + clear display
linx led red                   # led ring color
linx led 255,128,0             # custom rgb
linx led off                   # leds off
linx wake                      # wake from desktop/standby
linx version                   # firmware version
linx upload boot.jpg /usr/data/boot.jpg   # upload to device fs
```

ctrl+c stops playback. add `-a` for ambilight (led edge-matching).

### systemd service

```
systemctl --user enable --now linx    # start + autostart
systemctl --user stop linx            # stop
systemctl --user edit linx            # override default (matrix)
```

### config

optional toml at `/etc/linx.conf` or `~/.config/linx/config.toml`:

```toml
[display]
brightness = 80

[matrix]
duration = 60
fps = 30

[ambilight]
enabled = false
```

cli args override config. `--config /path/to/file.toml` for explicit config.

## how it works

des-cbc encrypted usb bulk transfers. key = iv = `slv3tuzx` (yeah, really). each command is a 512-byte packet: 500-byte plaintext, encrypted, padded to 512 with `[0xA1, 0x1A]` trailer.

**display layers** (bottom to top):
- **h264 decoder** — persistent framebuffer, survives stop_play
- **jpg background** (cmd 101) — opaque, covers h264
- **png overlay** (cmd 102) — transparent, composites on top

clearing after h264 playback requires pushing a black jpeg to the background layer. the h264 decoder framebuffer has no clear command — it just holds the last frame forever.

video encoding uses **nvenc** (h264_nvenc) when available — near-zero cpu. falls back to libx264 ultrafast.

## python api

```python
from linx import LCDDevice, LEDDevice, WIDTH, HEIGHT

lcd = LCDDevice()
lcd.connect()       # auto-wakes from desktop mode
lcd.init()
lcd.set_brightness(80)
lcd.prepare_display()
lcd.push_png(png_bytes)          # overlay layer
lcd.push_image(jpg_bytes, 101)   # background layer (covers h264)
lcd.play_h264('video.h264')
lcd.stop_play()
lcd.clear_layers()               # actually clears the screen
lcd.close()

led = LEDDevice()
led.connect()
led.set_all(255, 0, 0)
led.set_leds([(r, g, b)] * 60)
led.off()
led.close()
```

## known issues

- **uaccess requires local session** — udev rules use `uaccess` tag, needs systemd-logind. won't work over pure ssh. use `sudo linx` as fallback.
- **font paths are arch-specific** — matrix rain uses noto/dejavu mono from `/usr/share/fonts/`. falls back to pillow default on other distros.

## license

unlicense. do whatever you want with it.
