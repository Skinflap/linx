#!/usr/bin/env python3
"""
Linx — Linux driver for the Lian Li 8.8" Universal Screen

Controls the LCD display (480x1920), LED ring (45 RGB LEDs), and device mode
switching. Protocol reverse-engineered from L-Connect 3's lianli.lcd207.dll.

Usage:
    sudo python3 linx.py <command> [options]

Requires: pyusb, pycryptodome, Pillow, ffmpeg
"""

import sys
import struct
import time
import os
import signal
import subprocess
import tempfile
import io
import argparse
import random
import threading
from Crypto.Cipher import DES
import usb.core
import usb.util

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# USB IDs
LCD_VID, LCD_PID = 0x1CBE, 0xA088   # TI MCU — monitor mode (display commands)
HID_VID, HID_PID = 0x1A86, 0xAD21   # WCH chip — desktop/standby mode
LED_VID, LED_PID = 0x0416, 0x8050   # WCH chip — LED ring controller

# Display resolution (LEDController class, lines 8378-8380 in decompiled source)
# PID 0xA088 (41096) = LCD_88inchPid, managed by WinUsbLed/LEDController
WIDTH = 480
HEIGHT = 1920

# DES-CBC encryption — key and IV are both "slv3tuzx"
DES_KEY = b'slv3tuzx'

# SetMonitorMode magic: ASCII "5f3759df" (the fast inverse sqrt constant)
_MONITOR_MODE_CMD = bytes([53, 102, 51, 55, 53, 57, 100, 102])

# Command IDs (CmdType enum from lcd207.dll, line 15683)
CMD_GET_VER        = 10
CMD_REBOOT         = 11   # Switches to desktop mode — use with caution
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
CMD_PUSH_JPG       = 101  # JPG layer (opaque background) — broken on Linux >2KB
CMD_PUSH_PNG       = 102  # PNG layer (transparent overlay) — works at all sizes
CMD_START_PLAY1    = 119  # H.264 stream slot 1
CMD_START_PLAY2    = 120  # H.264 stream slot 2
CMD_START_PLAY     = 121  # H.264 stream slot 0 (primary)
CMD_QUERY_BLOCK    = 122
CMD_STOP_PLAY      = 123
CMD_SWITCH_DESKTOP = 150

# Daemon
PID_FILE = '/tmp/linx.pid'
LOG_FILE = '/tmp/linx.log'

# Timestamp base for command headers
_start_time = time.time()


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

def _ts():
    """Millisecond timestamp since process start, as 32-bit unsigned."""
    return int((time.time() - _start_time) * 1000) & 0xFFFFFFFF


def _des_encrypt(data):
    """DES-CBC encrypt with PKCS7 padding. Key = IV = 'slv3tuzx'."""
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv=DES_KEY)
    pad_len = 8 - (len(data) % 8)
    return cipher.encrypt(bytes(data) + bytes([pad_len] * pad_len))


def _make_header(cmd, data_at_8=None):
    """Build 512-byte encrypted command header.

    GetBaseCmdBuf: buf[0]=cmd, buf[2]=0x1A, buf[3]=0x6D, buf[4:8]=timestamp(LE)
    Encrypt 500 bytes -> copy into 512-byte packet -> trailer [0xA1, 0x1A]
    """
    buf = bytearray(500)
    buf[0] = cmd & 0xFF
    buf[2] = 0x1A
    buf[3] = 0x6D
    struct.pack_into('<I', buf, 4, _ts())
    if data_at_8:
        for i, b in enumerate(data_at_8):
            if 8 + i < 500:
                buf[8 + i] = b
    encrypted = _des_encrypt(buf)
    packet = bytearray(512)
    packet[:len(encrypted)] = encrypted[:512]
    packet[510] = 0xA1
    packet[511] = 0x1A
    return bytes(packet)


# ---------------------------------------------------------------------------
# Daemon helpers
# ---------------------------------------------------------------------------

def daemonize():
    """Fork to background, write PID file, redirect output to log."""
    pid = os.fork()
    if pid > 0:
        # Parent — write child PID and exit
        with open(PID_FILE, 'w') as f:
            f.write(str(pid))
        print(f"Running in background (PID {pid})")
        print(f"  Log: {LOG_FILE}")
        print(f"  Stop: sudo linx.py kill")
        sys.exit(0)
    # Child — new session, redirect stdio to log (line-buffered)
    os.setsid()
    log = open(LOG_FILE, 'a', buffering=1)
    os.dup2(log.fileno(), sys.stdout.fileno())
    os.dup2(log.fileno(), sys.stderr.fileno())
    sys.stdout = open(LOG_FILE, 'a', buffering=1)
    sys.stderr = open(LOG_FILE, 'a', buffering=1)
    devnull = open(os.devnull, 'r')
    os.dup2(devnull.fileno(), sys.stdin.fileno())
    # Write our actual PID (after fork)
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))
    print(f"[{time.strftime('%H:%M:%S')}] Linx daemon started (PID {os.getpid()})", flush=True)


def kill_daemon():
    """Kill a running Linx daemon."""
    if not os.path.exists(PID_FILE):
        print("No daemon running (no PID file)")
        return False
    with open(PID_FILE) as f:
        pid = int(f.read().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        # Wait for it to die
        for _ in range(20):
            time.sleep(0.1)
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
        else:
            os.kill(pid, signal.SIGKILL)
        print(f"Stopped daemon (PID {pid})")
    except ProcessLookupError:
        print(f"Daemon already stopped (stale PID {pid})")
    try:
        os.unlink(PID_FILE)
    except FileNotFoundError:
        pass
    return True


def cleanup_daemon():
    """Remove PID file on exit."""
    try:
        os.unlink(PID_FILE)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Mode switching
# ---------------------------------------------------------------------------

def wake_from_desktop():
    """Send SetMonitorMode to WCH HID device to wake the TI MCU.

    The device has two mutually exclusive USB modes:
    - Desktop mode: WCH HID (1a86:ad21) — standby, only accepts wake command
    - Monitor mode: TI MCU (1cbe:a088) — full display control

    Returns True if the TI MCU enumerated successfully.
    """
    hid = usb.core.find(idVendor=HID_VID, idProduct=HID_PID)
    if hid is None:
        return False
    try:
        if hid.is_kernel_driver_active(1):
            hid.detach_kernel_driver(1)
    except usb.core.USBError:
        pass
    try:
        hid.set_configuration()
    except usb.core.USBError:
        pass
    usb.util.claim_interface(hid, 1)
    pkt = bytearray(512)
    pkt[:len(_MONITOR_MODE_CMD)] = _MONITOR_MODE_CMD
    try:
        hid.write(0x02, bytes(pkt), timeout=2000)
        print("SetMonitorMode sent, waiting for TI MCU...")
    except usb.core.USBError:
        pass
    usb.util.release_interface(hid, 1)

    for _ in range(20):
        time.sleep(0.5)
        if usb.core.find(idVendor=LCD_VID, idProduct=LCD_PID):
            return True
    return False


# ---------------------------------------------------------------------------
# LCD display controller
# ---------------------------------------------------------------------------

class LCDDevice:
    """Controls the Lian Li 8.8\" LCD via DES-encrypted USB bulk transfers."""

    def __init__(self):
        self.dev = None
        self.h264_buf_len = 202752  # Default; queried from device before streaming

    # --- Connection ---

    def connect(self):
        """Find and claim the USB device. Auto-wakes from desktop mode."""
        self.dev = usb.core.find(idVendor=LCD_VID, idProduct=LCD_PID)
        if self.dev is None:
            if usb.core.find(idVendor=HID_VID, idProduct=HID_PID):
                print("Device in desktop mode, switching to monitor mode...")
                if wake_from_desktop():
                    self.dev = usb.core.find(idVendor=LCD_VID, idProduct=LCD_PID)
        if self.dev is None:
            return False
        if self.dev.is_kernel_driver_active(0):
            self.dev.detach_kernel_driver(0)
        try:
            self.dev.set_configuration()
        except usb.core.USBError:
            pass
        usb.util.claim_interface(self.dev, 0)
        try:
            print(f"Connected: {self.dev.manufacturer} {self.dev.product}")
        except (ValueError, usb.core.USBError):
            print(f"Connected: {LCD_VID:04x}:{LCD_PID:04x}")
        return True

    def close(self):
        """Release the USB interface."""
        if self.dev:
            try:
                usb.util.release_interface(self.dev, 0)
            except usb.core.USBError:
                pass
            self.dev = None

    def _reconnect(self):
        """Close and reopen. Matches ReInitDev from decompiled source."""
        try:
            usb.util.release_interface(self.dev, 0)
        except usb.core.USBError:
            pass
        try:
            usb.util.dispose_resources(self.dev)
        except usb.core.USBError:
            pass
        self.dev = None
        time.sleep(0.1)
        self.dev = usb.core.find(idVendor=LCD_VID, idProduct=LCD_PID)
        if self.dev is None:
            return False
        if self.dev.is_kernel_driver_active(0):
            self.dev.detach_kernel_driver(0)
        try:
            self.dev.set_configuration()
        except usb.core.USBError:
            pass
        usb.util.claim_interface(self.dev, 0)
        return True

    # --- Low-level I/O ---

    def _flush_read(self):
        """Drain stale data from read endpoint to prevent response desync."""
        while True:
            try:
                self.dev.read(0x81, 512, timeout=10)
            except (usb.core.USBTimeoutError, usb.core.USBError):
                break

    def _send_and_read(self, data, read=True):
        """Write data and optionally read response.

        Write timeout scales with payload size because the device is USB
        full-speed (12 Mbps). Read timeout is fixed at 2000ms.
        Retries once on write failure after reconnecting.
        """
        self._flush_read()
        write_ms = max(2000, len(data) // 500 + 2000)
        try:
            self.dev.write(0x01, data, timeout=write_ms)
        except usb.core.USBError:
            if not self._reconnect():
                return None
            try:
                self.dev.write(0x01, data, timeout=write_ms)
            except usb.core.USBError:
                return None
        if not read:
            return b''
        try:
            resp = bytes(self.dev.read(0x81, 512, timeout=2000))
            self._flush_read()
            return resp
        except (usb.core.USBTimeoutError, usb.core.USBError):
            return None

    def send_cmd(self, cmd, data=None):
        """Send an encrypted command and return the response."""
        return self._send_and_read(_make_header(cmd, data))

    def send_with_payload(self, cmd, payload, data_at_8=None):
        """Send encrypted header + raw payload as a single USB transfer.

        Used for image push and H.264 streaming where data follows the header.
        """
        header = _make_header(cmd, data_at_8)
        buf = bytearray(512 + len(payload))
        buf[0:512] = header
        buf[512:] = payload
        return self._send_and_read(bytes(buf))

    # --- Display commands ---

    def init(self):
        """Initialize device. Matches WinUsbH2S.InitDev(): SetFrameRate(30)."""
        self.set_framerate(30)

    def get_version(self):
        """Get firmware version string."""
        resp = self.send_cmd(CMD_GET_VER)
        if resp and len(resp) > 8:
            return resp[8:40].decode('ascii', errors='replace').rstrip('\x00')
        return None

    def set_brightness(self, level):
        """Set display brightness (0-100)."""
        return self.send_cmd(CMD_BRIGHTNESS, bytes([max(0, min(100, level))]))

    def set_rotation(self, rot):
        """Set display rotation (0-3)."""
        return self.send_cmd(CMD_ROTATE, bytes([rot & 0x03]))

    def set_framerate(self, fps):
        """Set display framerate (1-99)."""
        return self.send_cmd(CMD_SET_FRAMERATE, bytes([max(1, min(99, fps))]))

    def stop_play(self):
        """Stop H.264 playback."""
        return self.send_cmd(CMD_STOP_PLAY)

    def sync_clock(self, mode=2):
        """Sync device clock. mode: 0=disable, 1=enable, 2=sync only."""
        import datetime
        now = datetime.datetime.now()
        data = bytes([
            (now.year >> 8) & 0xFF, now.year & 0xFF,
            now.month, now.day, now.hour, now.minute, now.second,
            mode & 0xFF
        ])
        return self.send_cmd(CMD_SET_CLOCK, data)

    def stop_clock(self):
        """Stop the on-screen clock overlay."""
        return self.send_cmd(CMD_STOP_CLOCK, bytes([0]))

    def query_block(self):
        """Query H.264 buffer depth for all slots."""
        return self.send_cmd(CMD_QUERY_BLOCK)

    def check_h264_block(self):
        """Query H.264 buffer size from device."""
        resp = self.send_cmd(CMD_GET_H264_BLOCK)
        if resp and len(resp) > 11:
            size = (resp[8] << 24) | (resp[9] << 16) | (resp[10] << 8) | resp[11]
            if size > 0:
                self.h264_buf_len = size
                return size
        return self.h264_buf_len

    # --- Image push ---

    def push_image(self, image_bytes, cmd=CMD_PUSH_PNG):
        """Push image data to the device.

        cmd=CMD_PUSH_PNG (102) for PNG layer (transparent overlay) — reliable.
        cmd=CMD_PUSH_JPG (101) for JPG layer (opaque background) — broken on
        Linux for files >~2KB, so PNG is used for everything by default.
        """
        length = len(image_bytes)
        data = bytes([
            (length >> 24) & 0xFF, (length >> 16) & 0xFF,
            (length >> 8) & 0xFF, length & 0xFF
        ])
        return self.send_with_payload(cmd, image_bytes, data)

    def push_png(self, png_bytes):
        """Push PNG to the overlay layer."""
        return self.push_image(png_bytes, CMD_PUSH_PNG)

    def clear_layers(self):
        """Clear both display layers (PNG overlay + JPG background).

        Matches the clear sequence in LEDController.ApplyTemplate.
        Uses PNG command for both since JPEG is broken on Linux.
        """
        from PIL import Image
        # Clear PNG overlay (fully transparent)
        img = Image.new('RGBA', (WIDTH, HEIGHT), (0, 0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        self.push_image(buf.getvalue(), CMD_PUSH_PNG)
        # Clear JPG background (black)
        img = Image.new('RGB', (WIDTH, HEIGHT), (0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        self.push_image(buf.getvalue(), CMD_PUSH_PNG)

    def prepare_display(self):
        """Full display prep matching ApplyTemplate:
        SyncClock -> StopClock -> ClearPngLayer -> ClearJpgLayer
        """
        self.sync_clock(mode=2)
        self.stop_clock()
        self.clear_layers()

    # --- H.264 streaming ---

    def _wait_buffer(self, max_blocks=2, play_cmd=CMD_START_PLAY):
        """Poll QueryBlock until the device buffer has room."""
        buf_idx = {CMD_START_PLAY: 8, CMD_START_PLAY1: 9, CMD_START_PLAY2: 10}.get(play_cmd, 8)
        for _ in range(200):
            time.sleep(0.05)
            try:
                resp = self.send_cmd(CMD_QUERY_BLOCK)
            except usb.core.USBError:
                time.sleep(0.5)
                continue
            if resp and len(resp) > buf_idx and resp[buf_idx] <= max_blocks:
                return

    def play_h264(self, filepath, loop=True, play_cmd=CMD_START_PLAY, play_count=1):
        """Stream raw H.264 file to the device.

        Reads in h264_buf_len chunks, sends each with an encrypted header.
        30ms delay between chunks. Flow control via QueryBlock polling.
        Ctrl+C / SIGTERM to stop.
        """
        if not os.path.exists(filepath):
            print(f"File not found: {filepath}")
            return False

        self.check_h264_block()
        buf_len = self.h264_buf_len
        buf_idx = {CMD_START_PLAY: 8, CMD_START_PLAY1: 9, CMD_START_PLAY2: 10}.get(play_cmd, 8)

        try:
            while True:
                with open(filepath, 'rb') as f:
                    while True:
                        chunk = f.read(buf_len)
                        if not chunk:
                            break
                        data_len = len(chunk)
                        buf = bytearray(512 + data_len)
                        buf[512:] = chunk
                        header_data = bytes([
                            (data_len >> 24) & 0xFF, (data_len >> 16) & 0xFF,
                            (data_len >> 8) & 0xFF, data_len & 0xFF,
                            0, play_count & 0xFF,
                        ])
                        buf[0:512] = _make_header(play_cmd, header_data)
                        resp = self._send_and_read(bytes(buf))
                        time.sleep(0.03)
                        if resp and len(resp) > buf_idx and resp[buf_idx] > 3:
                            self._wait_buffer(2, play_cmd)

                if not loop:
                    break
        except KeyboardInterrupt:
            pass

        print(f"[{time.strftime('%H:%M:%S')}] Playback stopped")
        self.stop_play()
        return True

    # --- File upload ---

    def upload_file(self, data, target_path):
        """Upload a file to the device filesystem (e.g. /usr/data/boot.jpg)."""
        fname_bytes = target_path.encode('ascii')
        fname_len = len(fname_bytes)
        data_len = len(data)
        header_data = bytearray(492)
        header_data[0] = (fname_len >> 24) & 0xFF
        header_data[1] = (fname_len >> 16) & 0xFF
        header_data[2] = (fname_len >> 8) & 0xFF
        header_data[3] = fname_len & 0xFF
        header_data[4] = (data_len >> 24) & 0xFF
        header_data[5] = (data_len >> 16) & 0xFF
        header_data[6] = (data_len >> 8) & 0xFF
        header_data[7] = data_len & 0xFF
        header_data[8:8 + fname_len] = fname_bytes
        return self.send_with_payload(CMD_UPDATE_FIRMWARE, data, bytes(header_data))


# ---------------------------------------------------------------------------
# LED ring controller
# ---------------------------------------------------------------------------

class LEDDevice:
    """Controls the 60-LED RGB ring (0416:8050) via raw HID packets.

    The 8.8" screen LED ring has 60 LEDs in 3 groups of 20.
    L-Connect sends color data with isRead=false (fire-and-forget).
    """

    NUM_LEDS = 60
    LEDS_PER_GROUP = 20

    def __init__(self):
        self.dev = None

    def connect(self):
        self.dev = usb.core.find(idVendor=LED_VID, idProduct=LED_PID)
        if self.dev is None:
            return False
        if self.dev.is_kernel_driver_active(0):
            self.dev.detach_kernel_driver(0)
        self.dev.set_configuration()
        usb.util.claim_interface(self.dev, 0)
        return True

    def close(self):
        if self.dev:
            try:
                usb.util.release_interface(self.dev, 0)
            except usb.core.USBError:
                pass
            self.dev = None

    def _send(self, data, read=True):
        buf = bytearray(64)
        buf[:min(len(data), 64)] = data[:64]
        self.dev.write(0x01, bytes(buf), timeout=2000)
        if not read:
            return None
        try:
            return bytes(self.dev.read(0x81, 64, timeout=500))
        except (usb.core.USBTimeoutError, usb.core.USBError):
            return None

    def get_version(self):
        resp = self._send(bytes([16]), read=True)
        if resp and resp[0] == 16 and resp[1] > 0:
            return f"{resp[1]}_{resp[2]}"
        return None

    def set_leds(self, leds_rgb):
        """Set LED colors. leds_rgb = list of up to 60 (r, g, b) tuples.

        Matches the 8.8" SetEffect (line 10327-10333):
        - 3 groups of 20 LEDs, offsets 0/20/40
        - 60 bytes of RGB data per group
        - isRead=false (no response expected)
        """
        for group in range(3):
            pkt = bytearray(64)
            pkt[0] = 17
            pkt[1] = group * self.LEDS_PER_GROUP
            for i in range(self.LEDS_PER_GROUP):
                idx = group * self.LEDS_PER_GROUP + i
                if idx < len(leds_rgb):
                    r, g, b = leds_rgb[idx]
                    pkt[4 + i * 3] = r & 0xFF
                    pkt[4 + i * 3 + 1] = g & 0xFF
                    pkt[4 + i * 3 + 2] = b & 0xFF
            self._send(pkt, read=False)

    def set_all(self, r, g, b):
        """Set all LEDs to one color."""
        self.set_leds([(r, g, b)] * self.NUM_LEDS)

    def off(self):
        """Turn off all LEDs."""
        self.set_all(0, 0, 0)


# ---------------------------------------------------------------------------
# Ambilight — sample screen edges and drive LED ring
# ---------------------------------------------------------------------------

def sample_edge_colors(img, num_leds=60):
    """Sample colors from the perimeter of a PIL Image for LED edge-matching.

    Maps `num_leds` positions evenly around the image perimeter and returns
    the average color in a small region at each position.

    The screen is 480 wide x 1920 tall (portrait). Perimeter = 2*(480+1920) = 4800px.
    We walk: bottom edge (L->R), right edge (B->T), top edge (R->L), left edge (T->B).
    """
    w, h = img.size
    perimeter = 2 * (w + h)
    step = perimeter / num_leds
    sample_size = 8  # average an 8x8 block at each point
    colors = []

    for i in range(num_leds):
        pos = i * step
        # Bottom edge: left to right (y = h-1)
        if pos < w:
            cx, cy = int(pos), h - 1
        # Right edge: bottom to top (x = w-1)
        elif pos < w + h:
            cx, cy = w - 1, h - 1 - int(pos - w)
        # Top edge: right to left (y = 0)
        elif pos < 2 * w + h:
            cx, cy = w - 1 - int(pos - w - h), 0
        # Left edge: top to bottom (x = 0)
        else:
            cx, cy = 0, int(pos - 2 * w - h)

        # Sample a small block around the point
        x0 = max(0, cx - sample_size // 2)
        y0 = max(0, cy - sample_size // 2)
        x1 = min(w, x0 + sample_size)
        y1 = min(h, y0 + sample_size)
        region = img.crop((x0, y0, x1, y1))
        pixels = list(region.getdata() if not hasattr(region, 'get_flattened_data')
                      else region.get_flattened_data())
        if pixels:
            r = sum(p[0] for p in pixels) // len(pixels)
            g = sum(p[1] for p in pixels) // len(pixels)
            b = sum(p[2] for p in pixels) // len(pixels)
            colors.append((r, g, b))
        else:
            colors.append((0, 0, 0))

    return colors


class AmbilightThread(threading.Thread):
    """Background thread that updates LEDs from a shared frame reference.

    The main loop sets `self.frame` to a PIL Image whenever it has a new one.
    This thread picks it up, samples edges, and sends to the LED device.
    Runs at ~10 LED updates/second to avoid overwhelming the HID bus.
    """

    def __init__(self, led_device, grayscale_max=0):
        super().__init__(daemon=True)
        self.led = led_device
        self.frame = None
        self._lock = threading.Lock()
        self.running = True
        self._error_count = 0
        self.grayscale_max = grayscale_max  # 0 = full color, >0 = grayscale capped at this value

    def update_frame(self, img):
        """Called by the producer (main thread) with a new PIL Image."""
        with self._lock:
            self.frame = img

    def run(self):
        last_frame = None
        while self.running:
            with self._lock:
                frame = self.frame
            if frame is not None and frame is not last_frame:
                last_frame = frame
                try:
                    colors = sample_edge_colors(frame)
                    if self.grayscale_max > 0:
                        # Convert to grayscale intensity, scaled to max brightness
                        gmax = self.grayscale_max
                        colors = [
                            (min(gmax, int((r * 0.299 + g * 0.587 + b * 0.114) / 255.0 * gmax)),) * 3
                            for r, g, b in colors
                        ]
                    self.led.set_leds(colors)
                    self._error_count = 0
                except Exception as e:
                    self._error_count += 1
                    if self._error_count <= 3:
                        print(f"[ambilight] LED error: {e}", flush=True)
            time.sleep(0.1)  # ~10 updates/sec

    def stop(self):
        self.running = False


# ---------------------------------------------------------------------------
# Content generation helpers
# ---------------------------------------------------------------------------

def encode_h264(input_path, width=WIDTH, height=HEIGHT):
    """Convert any image/video to raw H.264 for the device.

    Encoding matches L-Connect 3: libx264, no B-frames, ultrafast preset.
    """
    outpath = tempfile.mktemp(suffix='.h264')
    result = subprocess.run([
        'ffmpeg', '-y', '-i', input_path,
        '-vf', f'scale={width}:{height}:force_original_aspect_ratio=decrease,'
               f'pad={width}:{height}:(ow-iw)/2:(oh-ih)/2',
        '-vcodec', 'libx264', '-x264opts', 'bframes=0',
        '-threads', '4', '-preset', 'ultrafast',
        '-pix_fmt', 'yuv420p', '-an',
        '-f', 'h264', outpath
    ], capture_output=True)
    if result.returncode != 0:
        print(f"FFmpeg error: {result.stderr.decode()[:500]}")
        return None
    return outpath


def generate_solid_h264(color='red', width=WIDTH, height=HEIGHT, duration=5, fps=30):
    """Generate a solid color H.264 test clip."""
    colors = {
        'red': '0xFF0000', 'green': '0x00FF00', 'blue': '0x0000FF',
        'white': '0xFFFFFF', 'black': '0x000000', 'cyan': '0x00FFFF',
        'magenta': '0xFF00FF', 'yellow': '0xFFFF00',
    }
    c = colors.get(color, color)
    outpath = tempfile.mktemp(suffix='.h264')
    subprocess.run([
        'ffmpeg', '-y', '-f', 'lavfi',
        '-i', f'color=c={c}:s={width}x{height}:d={duration}:r={fps}',
        '-vcodec', 'libx264', '-x264opts', 'bframes=0',
        '-threads', '4', '-preset', 'ultrafast',
        '-pix_fmt', 'yuv420p',
        '-f', 'h264', outpath
    ], capture_output=True, check=True)
    return outpath


def generate_matrix_h264(width=WIDTH, height=HEIGHT, duration=30, fps=30,
                         ambilight=None):
    """Generate a Matrix-style digital rain animation as H.264.

    Renders frames with Pillow, pipes to ffmpeg for encoding.
    If `ambilight` is an AmbilightThread, feeds frames to it for LED sync.
    """
    from PIL import Image, ImageDraw, ImageFont

    outpath = tempfile.mktemp(suffix='.h264')
    total_frames = duration * fps
    char_w, char_h = 10, 16
    cols = width // char_w
    rows = height // char_h

    drops = [random.randint(-rows, 0) for _ in range(cols)]
    speeds = [random.randint(1, 3) for _ in range(cols)]
    chars = "0123456789ABCDEFabcdef@#$%&*<>{}[]|/\\~"

    try:
        font = ImageFont.truetype("/usr/share/fonts/noto/NotoSansMono-Regular.ttf", 14)
    except (OSError, IOError):
        try:
            font = ImageFont.truetype("/usr/share/fonts/TTF/DejaVuSansMono.ttf", 14)
        except (OSError, IOError):
            font = ImageFont.load_default()

    proc = subprocess.Popen([
        'ffmpeg', '-y', '-f', 'rawvideo', '-pix_fmt', 'rgb24',
        '-s', f'{width}x{height}', '-r', str(fps), '-i', '-',
        '-vcodec', 'libx264', '-x264opts', 'bframes=0',
        '-threads', '4', '-preset', 'ultrafast',
        '-pix_fmt', 'yuv420p',
        '-f', 'h264', outpath
    ], stdin=subprocess.PIPE, stderr=subprocess.PIPE)

    print(f"Generating {total_frames} frames ({duration}s at {fps}fps)...")
    for frame_num in range(total_frames):
        img = Image.new('RGB', (width, height), (0, 0, 0))
        draw = ImageDraw.Draw(img)

        for col in range(cols):
            x = col * char_w
            head_row = drops[col]

            for trail in range(rows):
                row = head_row - trail
                if 0 <= row < rows:
                    y = row * char_h
                    ch = random.choice(chars)
                    if trail == 0:
                        color = (200, 255, 200)
                    elif trail < 4:
                        color = (0, 255, 0)
                    elif trail < 12:
                        g = max(0, 200 - trail * 15)
                        color = (0, g, 0)
                    else:
                        break
                    draw.text((x, y), ch, fill=color, font=font)

            drops[col] += speeds[col]
            if drops[col] - 12 > rows:
                drops[col] = random.randint(-10, 0)
                speeds[col] = random.randint(1, 3)

        # Feed frame to ambilight if active
        if ambilight and frame_num % 3 == 0:
            ambilight.update_frame(img.copy())

        proc.stdin.write(img.tobytes())
        if (frame_num + 1) % (fps * 5) == 0:
            print(f"  {frame_num + 1}/{total_frames} frames...")

    proc.stdin.close()
    proc.wait()
    size = os.path.getsize(outpath)
    print(f"Done: {size / 1024 / 1024:.1f} MB")
    return outpath


def play_h264_with_ambilight(lcd, led, filepath, loop=True, ambi=None, grayscale_max=0):
    """Stream H.264 to LCD while decoding frames in parallel for LED ambilight.

    Runs ffmpeg to decode the video into raw frames in a background thread,
    feeds those frames to the ambilight sampler, while the main thread
    streams the original H.264 to the device.

    If `ambi` is provided, reuses that AmbilightThread instead of creating a new one.
    """
    from PIL import Image

    own_ambi = ambi is None
    if own_ambi:
        ambi = AmbilightThread(led, grayscale_max=grayscale_max)
        ambi.start()

    # Decode at reduced resolution for LED sampling — much faster
    sample_w, sample_h = WIDTH // 4, HEIGHT // 4
    frame_size = sample_w * sample_h * 3

    def _start_decoder():
        return subprocess.Popen([
            'ffmpeg', '-f', 'h264', '-i', filepath,
            '-f', 'rawvideo', '-pix_fmt', 'rgb24',
            '-s', f'{sample_w}x{sample_h}', '-r', '10',
            '-v', 'error', '-'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    state = {'decoder': _start_decoder()}

    def decode_loop():
        while ambi.running:
            dec = state['decoder']
            data = dec.stdout.read(frame_size)
            if not data or len(data) < frame_size:
                # EOF — if looping, restart decoder
                if loop and ambi.running:
                    try:
                        dec.terminate()
                        dec.wait(timeout=2)
                    except Exception:
                        pass
                    state['decoder'] = _start_decoder()
                    continue
                break
            try:
                img = Image.frombytes('RGB', (sample_w, sample_h), data)
                ambi.update_frame(img)
            except Exception as e:
                print(f"[ambilight] decode error: {e}", flush=True)

    decode_thread = threading.Thread(target=decode_loop, daemon=True)
    decode_thread.start()

    try:
        lcd.play_h264(filepath, loop=loop)
    finally:
        ambi.stop()
        try:
            state['decoder'].terminate()
            state['decoder'].wait(timeout=2)
        except (subprocess.TimeoutExpired, Exception):
            try:
                state['decoder'].kill()
            except Exception:
                pass
        if own_ambi:
            led.off()


def make_png(width=WIDTH, height=HEIGHT, color=(255, 0, 0)):
    """Generate a solid color PNG at device resolution."""
    from PIL import Image
    img = Image.new('RGB', (width, height), color)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

LED_COLORS = {
    'off': (0, 0, 0), 'red': (255, 0, 0), 'green': (0, 255, 0),
    'blue': (0, 0, 255), 'white': (255, 255, 255), 'cyan': (0, 255, 255),
    'magenta': (255, 0, 255), 'yellow': (255, 255, 0),
    'charcoal': (0x8a, 0x92, 0xa4),
}


def main():
    parser = argparse.ArgumentParser(
        prog='linx',
        description='Linx — Linux driver for the Lian Li 8.8" Universal Screen',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""Display: {WIDTH}x{HEIGHT} | LCD: {LCD_VID:04x}:{LCD_PID:04x} | LED: {LED_VID:04x}:{LED_PID:04x}

Examples:
  sudo %(prog)s matrix -d        Matrix screensaver (background)
  sudo %(prog)s play video.mp4   Play a video (loops, Ctrl+C to stop)
  sudo %(prog)s play clip.mp4 -d Run video in background
  sudo %(prog)s image photo.png  Display an image
  sudo %(prog)s color blue       Solid color
  sudo %(prog)s brightness 50    Set brightness
  sudo %(prog)s led red          Set LED ring color
  sudo %(prog)s kill             Stop background daemon
""")
    sub = parser.add_subparsers(dest='command')

    sub.add_parser('test', help='Test connection and show firmware info')
    sub.add_parser('version', help='Show firmware version')

    p = sub.add_parser('image', help='Display an image file (PNG/JPG)')
    p.add_argument('file', help='Image file to display')
    p.add_argument('--ambilight', '-a', action='store_true',
                   help='Set LED ring to match image edges')

    p = sub.add_parser('play', help='Play a video file (any format ffmpeg supports)')
    p.add_argument('file', help='Video file to play')
    p.add_argument('--no-loop', action='store_true', help='Play once instead of looping')
    p.add_argument('--daemon', '-d', action='store_true', help='Run in background')
    p.add_argument('--ambilight', '-a', action='store_true',
                   help='Sync LED ring to video edges')
    p.add_argument('--grayscale', '-g', type=int, default=0, metavar='MAX',
                   help='Ambilight grayscale mode: max brightness 1-255 (e.g. -g 2)')

    p = sub.add_parser('color', help='Display a solid color')
    p.add_argument('color', metavar='COLOR',
                   help='Color name or hex (e.g. red, 0xFF8800)')
    p.add_argument('--daemon', '-d', action='store_true', help='Run in background')
    p.add_argument('--ambilight', '-a', action='store_true',
                   help='Set LED ring to match color')

    p = sub.add_parser('matrix', help='Matrix rain screensaver')
    p.add_argument('--daemon', '-d', action='store_true', help='Run in background')
    p.add_argument('--ambilight', '-a', action='store_true',
                   help='Sync LED ring to screen edges')

    p = sub.add_parser('brightness', help='Set display brightness')
    p.add_argument('level', type=int, metavar='0-100')

    sub.add_parser('stop', help='Stop video playback')
    sub.add_parser('wake', help='Wake device from desktop/standby mode')
    sub.add_parser('kill', help='Stop background Linx daemon')

    p = sub.add_parser('led', help='Set LED ring color')
    p.add_argument('color', metavar='COLOR',
                   help='Color name (red, green, blue, white, off, ...) or R,G,B')

    p = sub.add_parser('upload', help='Upload file to device filesystem')
    p.add_argument('file', help='Local file to upload')
    p.add_argument('target', help='Device path (e.g. /usr/data/boot.jpg)')

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # --- Kill daemon ---
    if args.command == 'kill':
        kill_daemon()
        # Also send stop to device in case it's mid-playback
        lcd = LCDDevice()
        if lcd.connect():
            lcd.stop_play()
            lcd.close()
        return

    # --- LED (no LCD needed) ---
    if args.command == 'led':
        led = LEDDevice()
        if not led.connect():
            print(f"LED device not found ({LED_VID:04x}:{LED_PID:04x})")
            sys.exit(1)
        if args.color in LED_COLORS:
            r, g, b = LED_COLORS[args.color]
        elif ',' in args.color:
            try:
                r, g, b = (int(x) for x in args.color.split(','))
            except ValueError:
                print(f"Invalid RGB: {args.color} (expected R,G,B e.g. 255,128,0)")
                sys.exit(1)
        else:
            print(f"Unknown color: {args.color}")
            print(f"Available: {', '.join(LED_COLORS.keys())}, or R,G,B")
            sys.exit(1)
        led.set_all(r, g, b)
        print(f"LEDs: ({r}, {g}, {b})")
        led.close()
        return

    # --- Wake (no LCD needed) ---
    if args.command == 'wake':
        if usb.core.find(idVendor=LCD_VID, idProduct=LCD_PID):
            print("Already in monitor mode")
        elif wake_from_desktop():
            print("Switched to monitor mode")
        else:
            print("Failed — device not found in either mode")
        return

    # --- Daemon mode: fork before connecting to devices ---
    use_daemon = getattr(args, 'daemon', False)
    if use_daemon:
        # Kill any existing daemon first
        if os.path.exists(PID_FILE):
            kill_daemon()
        daemonize()
        # Register cleanup for the child
        import atexit
        atexit.register(cleanup_daemon)
        # Handle SIGTERM gracefully
        def _sigterm(signum, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, _sigterm)

    # --- LCD commands ---
    lcd = LCDDevice()
    if not lcd.connect():
        print("LCD not found. Is the device plugged in?")
        print(f"  Monitor mode: {LCD_VID:04x}:{LCD_PID:04x}")
        print(f"  Desktop mode: {HID_VID:04x}:{HID_PID:04x}")
        print("  Try: sudo linx.py wake")
        sys.exit(1)

    # Connect LED for ambilight if requested (--grayscale implies --ambilight)
    grayscale_max = getattr(args, 'grayscale', 0)
    use_ambilight = getattr(args, 'ambilight', False) or grayscale_max > 0
    led = None
    if use_ambilight:
        led = LEDDevice()
        if not led.connect():
            print("LED device not found — ambilight disabled")
            led = None
            use_ambilight = False

    try:
        if args.command == 'test':
            lcd.init()
            ver = lcd.get_version()
            print(f"Firmware:   {ver or 'unknown'}")
            print(f"Resolution: {WIDTH}x{HEIGHT}")
            print(f"H.264 buf:  {lcd.check_h264_block()} bytes")

        elif args.command == 'version':
            ver = lcd.get_version()
            print(ver or "No response")

        elif args.command == 'image':
            from PIL import Image
            lcd.init()
            lcd.prepare_display()
            img = Image.open(args.file).convert('RGB')
            img = img.resize((WIDTH, HEIGHT), Image.LANCZOS)
            # Ambilight: set LEDs to match image edges
            if use_ambilight:
                colors = sample_edge_colors(img)
                led.set_leds(colors)
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            png_data = buf.getvalue()
            print(f"Pushing {args.file} ({len(png_data)} bytes, {WIDTH}x{HEIGHT})...")
            resp = lcd.push_png(png_data)
            print("Done" if resp else "No response")

        elif args.command == 'play':
            lcd.init()
            lcd.prepare_display()
            filepath = args.file
            if not filepath.endswith('.h264'):
                print(f"Encoding {filepath}...")
                filepath = encode_h264(filepath)
                if not filepath:
                    sys.exit(1)
            print(f"Streaming ({os.path.getsize(filepath)} bytes)...")
            if use_ambilight:
                play_h264_with_ambilight(lcd, led, filepath,
                                         loop=not args.no_loop,
                                         grayscale_max=grayscale_max)
            else:
                lcd.play_h264(filepath, loop=not args.no_loop)
            if not args.file.endswith('.h264'):
                os.unlink(filepath)

        elif args.command == 'color':
            lcd.init()
            lcd.prepare_display()
            # Set LEDs to match the solid color
            if use_ambilight and args.color in LED_COLORS:
                led.set_all(*LED_COLORS[args.color])
            h264 = generate_solid_h264(args.color)
            try:
                lcd.play_h264(h264, loop=True)
            finally:
                os.unlink(h264)

        elif args.command == 'matrix':
            lcd.init()
            lcd.prepare_display()
            # Create one ambilight thread, used during both generation and playback
            ambi = None
            if use_ambilight:
                ambi = AmbilightThread(led)
                ambi.start()
            h264 = generate_matrix_h264(duration=60, ambilight=ambi)
            try:
                if use_ambilight:
                    # Reuse the same ambilight thread for playback
                    play_h264_with_ambilight(lcd, led, h264, loop=True, ambi=ambi)
                else:
                    lcd.play_h264(h264, loop=True)
            finally:
                if ambi:
                    ambi.stop()
                os.unlink(h264)

        elif args.command == 'brightness':
            lcd.set_brightness(args.level)
            print(f"Brightness: {args.level}")

        elif args.command == 'stop':
            lcd.stop_play()
            print("Stopped")

        elif args.command == 'upload':
            with open(args.file, 'rb') as f:
                data = f.read()
            print(f"Uploading {len(data)} bytes to {args.target}...")
            resp = lcd.upload_file(data, args.target)
            print("Done" if resp else "No response")

    finally:
        lcd.close()
        if led:
            led.off()
            led.close()


if __name__ == '__main__':
    main()
