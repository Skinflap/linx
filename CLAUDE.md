# CLAUDE.md — Linx

## What Linx Is

Linx is a universal Linux device controller. It reverse-engineers proprietary USB protocols and replaces vendor Windows-only software with direct pyusb drivers. One tool, all devices, no bloatware.

Currently controls the Lian Li 8.8" Universal Screen (LCD + LED ring). Built to grow — every new device Mitchell plugs in that lacks Linux support gets added here.

## Owner

Mitchell. Arch Linux. No patience for "install the Windows app." If it's plugged in via USB, Linx should own it.

## Current Capabilities

### Lian Li 8.8" Universal Screen (CONFIRMED WORKING)

Protocol reverse-engineered from L-Connect 3's `lianli.lcd207.dll` (decompiled C#, 18,418 lines at `/tmp/lcd207_full.cs`).

**Three USB devices on one internal hub (`1a86:8091`):**

| Component | USB ID | Interface | Status |
|---|---|---|---|
| LCD (monitor mode) | `1cbe:a088` | TI MCU, bulk transfers | Working |
| LCD (desktop/standby) | `1a86:ad21` | WCH HID | Working (wake only) |
| LED ring | `0416:8050` | WCH chip, HID | Working |

**LCD features:**
- PNG image push (cmd 102) — works at all sizes
- H.264 video streaming (cmd 121) — 480x1920, looping, flow control
- Brightness control (cmd 14) — 0-100%
- Layer system — JPG background + PNG overlay + H.264 video layer
- Mode switching — desktop→monitor via HID magic bytes
- Matrix rain screensaver
- Background daemon mode (`-d`) with PID file
- Firmware version query

**LED ring features:**
- 60 RGB LEDs in 3 groups of 20 (offsets 0/20/40)
- Individual LED control or set-all
- Ambilight mode (`-a`) — samples screen edge pixels, drives LEDs to match
- Named colors and custom RGB values

**Resolution:** 480x1920 portrait. Device handles orientation.

**Encryption:** DES-CBC, key=IV=`slv3tuzx`. Every command is a 500-byte plaintext buffer, encrypted, padded to 512 bytes with `[0xA1, 0x1A]` trailer.

### What Does NOT Work

- **JPEG push (cmd 101):** Broken on Linux for files >~2KB. Device never responds under libusb. PNG used for everything instead.
- **CMD_REBOOT (11):** Switches to desktop mode. Never use — recovery requires HID wake.

## Recent Failures (2025-02-27)

### AIO RGB Controller — Not Identified
- Mitchell plugged in a Litehaus RGB floating orb (AIO cooler with inner + outer LED ring)
- Connected via external motherboard USB
- **Could not find it in `lsusb`** — every device was accounted for (Lian Li screen, ASUS AURA, mouse, keyboard, Scarlett, WiFi, Xbox controller)
- OpenRGB detected it under ASUS AURA controller with 3 addressable zones ('Aura Addressable 1/2/3') but `openrgb -d 0 -z N -m static -c COLOR` commands had zero visible effect on the AIO
- **Root cause unknown.** Either: the AIO isn't on AURA headers, OpenRGB's AURA USB HID driver doesn't reach the physical zones, or the device needs a different protocol entirely
- **Next step:** Unplug/replug to diff `lsusb` and isolate the USB ID. Then reverse-engineer its protocol like we did with the Lian Li screen

### OpenRGB
- Installed (`pacman -S openrgb`, v1.0rc2) but unreliable
- `i2c_smbus_linux` warnings on every invocation (harmless — SMBus RAM scan failing, not related to USB HID devices)
- AURA zone commands produced no visible effect on the AIO
- OpenRGB is a fallback/reference, not the solution. Linx's approach (direct USB protocol) is more reliable

## Architecture

Single file: `linx.py` (~1170 lines). No framework, no abstraction layers.

**Key classes:**
- `LCDDevice` — LCD display control (connect, init, push images, stream H.264, brightness, layers)
- `LEDDevice` — LED ring control (connect, set_all, set_leds, off)
- CLI via argparse — `sudo python3 linx.py <command> [options]`

**Dependencies:** pyusb, pycryptodome, Pillow, ffmpeg (system)

**Requires root** for direct USB access. Udev rules available to avoid this (see README.md).

## The Endgame

Linx becomes Mitchell's single controller for every RGB/display/peripheral device on his system that lacks native Linux support. The pattern is always the same:

1. **Identify** — find the device on USB (`lsusb`, unplug/replug diff)
2. **Reverse-engineer** — sniff the protocol (Wireshark USB capture, decompile vendor DLL/app, or brute-force probe endpoints)
3. **Implement** — add a new device class to Linx with pyusb direct control
4. **CLI** — expose it through the existing argparse interface

**Planned devices:**
- AIO cooler (Litehaus RGB floating orb) — inner ring + outer ring, individual LED control
- Any future RGB/peripheral Mitchell plugs in that only ships with Windows software

**Design principles:**
- Direct USB. No middleware (OpenRGB, vendor daemons). Linx owns the wire.
- Single file until complexity demands otherwise. No premature architecture.
- Every device gets named-color support, custom RGB, and off
- Ambilight-style reactive modes where applicable
- Background daemon mode for persistent effects
- Zero dependencies beyond pyusb + device-specific crypto/encoding libs

## Key Files

| File | Purpose |
|---|---|
| `linx.py` | The entire driver. All device classes, CLI, everything. |
| `README.md` | Usage docs, hardware table, API examples |
| `requirements.txt` | Python deps (pyusb, pycryptodome, Pillow) |
| `figure_box.h264`, `figure_smoke.h264` | Pre-encoded test videos for the LCD |

## Reference Material

| File | What |
|---|---|
| `/tmp/lcd207_full.cs` | Decompiled L-Connect 3 source (18,418 lines) — the Rosetta Stone for the Lian Li protocol |
| `/home/skinflap/.claude/projects/-home-skinflap-Projects-lianli-screen/memory/MEMORY.md` | Detailed protocol notes from reverse-engineering sessions |

## Commands

```bash
# LCD
sudo python3 linx.py test                    # test connection
sudo python3 linx.py image photo.png         # display image
sudo python3 linx.py play video.mp4          # stream video (loops)
sudo python3 linx.py color red               # solid color
sudo python3 linx.py matrix                  # matrix screensaver
sudo python3 linx.py brightness 75           # 0-100
sudo python3 linx.py stop                    # stop playback
sudo python3 linx.py wake                    # exit standby mode
sudo python3 linx.py version                 # firmware version

# LED ring
sudo python3 linx.py led red                 # named color
sudo python3 linx.py led 139,0,0             # custom RGB
sudo python3 linx.py led off                 # lights out

# Modes
sudo python3 linx.py matrix -a               # matrix + ambilight
sudo python3 linx.py play video.mp4 -d -a    # video + background + ambilight
sudo python3 linx.py kill                    # stop background daemon
```

## Rules

1. Never send CMD_REBOOT (11)
2. Never change rotation without Mitchell asking
3. Never probe unknown hardware blindly — read decompiled source or sniff protocol first
4. Use PNG (cmd 102) for all image pushes — JPEG is broken on Linux
5. LED color commands use `isRead=false` (fire-and-forget), not SendAndRead
6. Flush USB read buffer before send AND after read to prevent desync
7. Write timeout 2000ms+ (Windows source uses 200ms, too tight for libusb)
