# Linx

Linux driver for the **Lian Li 8.8" Universal Screen** — the LCD + LED ring combo found in Lian Li cases (e.g. Lancool III).

Reverse-engineered from L-Connect 3's `lianli.lcd207.dll`. No Windows required. Fuckers.

## Hardware

| Component | USB ID | Description |
| - | - | - |
| LCD (monitor mode) | `1cbe:a088` | TI MCU — all display commands |
| LCD (desktop mode) | `1a86:ad21` | WCH HID — standby, wake only |
| LED ring | `0416:8050` | 60 RGB LEDs, 3 groups of 20 |


The LCD has two mutually exclusive USB modes. In **monitor mode** (TI MCU), it accepts display commands. In **desktop mode** (WCH HID), it's in standby use `linx.py wake` to switch it back.

Display resolution: **480x1920** (portrait). The device firmware handles orientation.

## Requirements

```
sudo pacman -S python-pyusb python-pycryptodome python-pillow ffmpeg
```

Or via pip:

```
pip install pyusb pycryptodome Pillow
```

FFmpeg is needed for video encoding (`ffmpeg` must be in PATH).

## Usage

All commands require root (for USB access):

```
\# Test connection  
sudo python3 linx.py test  
  
\# Display an image (any format Pillow supports)  
sudo python3 linx.py image photo.png  
sudo python3 linx.py image wallpaper.jpg  
  
\# Play a video (any format ffmpeg supports, loops by default)  
sudo python3 linx.py play video.mp4  
sudo python3 linx.py play clip.gif  
sudo python3 linx.py play animation.mp4 --no-loop  
  
\# Solid color  
sudo python3 linx.py color red  
sudo python3 linx.py color cyan  
  
\# Matrix rain screensaver  
sudo python3 linx.py matrix  
  
\# Adjust brightness (0-100)  
sudo python3 linx.py brightness 75  
  
\# Stop video playback  
sudo python3 linx.py stop  
  
\# LED ring control  
sudo python3 linx.py led red  
sudo python3 linx.py led 255,128,0    \# custom RGB  
sudo python3 linx.py led off  
  
\# Wake from desktop/standby mode  
sudo python3 linx.py wake  
  
\# Show firmware version  
sudo python3 linx.py version  
  
\# Upload file to device (e.g. custom boot logo)  
sudo python3 linx.py upload boot.jpg /usr/data/boot.jpg
```

Press **Ctrl+C** to stop video playback or the matrix screensaver.

### Background mode

Add `-d` to run in the background — your terminal stays free:

```
sudo python3 linx.py matrix -d           \# matrix screensaver, backgrounded  
sudo python3 linx.py play video.mp4 -d   \# video, backgrounded  
sudo python3 linx.py kill                 \# stop the daemon
```

Logs go to `/tmp/linx.log`. PID written to `/tmp/linx.pid`.

### Ambilight (LED edge-matching)

Add `-a` to sync the LED ring to whatever's on screen — samples edge pixels and drives the 60 LEDs to match:

```
sudo python3 linx.py matrix -a           \# green glow while matrix runs  
sudo python3 linx.py play video.mp4 -a   \# LEDs follow the video  
sudo python3 linx.py image photo.png -a  \# LEDs match image edges  
sudo python3 linx.py matrix -d -a        \# both: background + ambilight
```

## How It Works

The LCD uses DES-CBC encrypted USB bulk transfers (key = IV = `slv3tuzx`). Each command is a 512-byte packet: 500-byte plaintext command buffer, encrypted, padded to 512 bytes with a `\[0xA1, 0x1A\]` trailer.

**Display layers:**

- **JPG layer** (cmd 101): opaque background

- **PNG layer** (cmd 102): transparent overlay composited on top

- **H.264 video** (cmd 121): replaces background; PNG overlay still composites on top

On Linux, the JPEG push command is unreliable for files \>2KB, so PNG is used for all image operations.

**H.264 streaming** sends raw H.264 data in ~200KB chunks, each prefixed with an encrypted header. The device has a 3-block buffer with flow control — the driver polls `QueryBlock` when the buffer is full.

## Python API

```
from linx import LCDDevice, LEDDevice, WIDTH, HEIGHT  
  
\# LCD  
lcd = LCDDevice()  
lcd.connect()  
lcd.init()  
lcd.set\_brightness(80)  
lcd.prepare\_display()       \# clear layers  
lcd.push\_png(png\_bytes)     \# push a PNG image  
lcd.play\_h264('video.h264') \# stream H.264 (loops, Ctrl+C to stop)  
lcd.stop\_play()  
lcd.close()  
  
\# LED ring  
led = LEDDevice()  
led.connect()  
led.set\_all(255, 0, 0)     \# all red  
led.set\_leds(\[(r,g,b)\] \* 60)  \# individual control  
led.off()  
led.close()
```

## Known Issues

- **JPEG push broken on Linux**: The device never responds to JPEG (cmd 101) for files larger than ~2KB under libusb. PNG (cmd 102) works at all sizes. The driver uses PNG for everything.

- **Requires root**: Direct USB access via pyusb needs root. You can add a udev rule to avoid this:

- ```
\# /etc/udev/rules.d/99-lianli-screen.rules  
SUBSYSTEM=="usb", ATTR\{idVendor\}=="1cbe", ATTR\{idProduct\}=="a088", MODE="0666"  
SUBSYSTEM=="usb", ATTR\{idVendor\}=="1a86", ATTR\{idProduct\}=="ad21", MODE="0666"  
SUBSYSTEM=="usb", ATTR\{idVendor\}=="0416", ATTR\{idProduct\}=="8050", MODE="0666"
```

- Then `sudo udevadm control --reload-rules && sudo udevadm trigger`.

## License

Do whatever you want with it idk wtf I’m doing  
t(-\_- t)

