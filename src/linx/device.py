"""USB device controllers for the LCD display and LED ring."""

import io
import os
import struct
import time
import usb.core
import usb.util

from .protocol import (
    LCD_VID, LCD_PID, HID_VID, HID_PID, LED_VID, LED_PID,
    WIDTH, HEIGHT,
    CMD_GET_VER, CMD_REBOOT, CMD_BRIGHTNESS, CMD_ROTATE, CMD_SET_FRAMERATE,
    CMD_GET_H264_BLOCK, CMD_PUSH_JPG, CMD_PUSH_PNG,
    CMD_START_PLAY, CMD_START_PLAY1, CMD_START_PLAY2,
    CMD_QUERY_BLOCK, CMD_STOP_PLAY, CMD_SWITCH_DESKTOP,
    CMD_SET_CLOCK, CMD_STOP_CLOCK,
    CMD_UPDATE_FIRMWARE,
    make_header,
)
from .wake import wake_from_desktop


# ---------------------------------------------------------------------------
# LCD display controller
# ---------------------------------------------------------------------------

class LCDDevice:
    """Controls the Lian Li 8.8" LCD via DES-encrypted USB bulk transfers."""

    def __init__(self):
        self.dev = None
        self.h264_buf_len = 202752  # Default; queried from device before streaming
        self._stop = False

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
        return self._send_and_read(make_header(cmd, data))

    def send_with_payload(self, cmd, payload, data_at_8=None):
        """Send encrypted header + raw payload as a single USB transfer.

        Used for image push and H.264 streaming where data follows the header.
        """
        header = make_header(cmd, data_at_8)
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

    def switch_desktop(self):
        """Send CMD_SWITCH_DESKTOP (150) firmware command.

        This is a firmware-level command sent over the encrypted USB protocol
        to the TI MCU. Distinct from the physical mode switch via WCH HID.
        """
        return self.send_cmd(CMD_SWITCH_DESKTOP)

    def reboot(self):
        """Send CMD_REBOOT (11) -- device switches to desktop mode."""
        return self.send_cmd(CMD_REBOOT)

    def clear_display(self, strategy):
        """Attempt to clear the H.264 framebuffer. Returns result string.

        Strategies (numbered for systematic testing):
          1: CMD_SWITCH_DESKTOP firmware command
          2: stop + small black JPEG via CMD_PUSH_JPG (background layer)
          3: stop + single-frame black H.264 (overwrite decoder buffer)
          4: stop + all three layers (JPG + PNG + stop_play)
          5: CMD_REBOOT (nuclear -- device returns to desktop mode)
        """
        ts = time.strftime('%H:%M:%S')

        if strategy == 1:
            print(f"[{ts}] Strategy 1: CMD_SWITCH_DESKTOP (150)")
            self.stop_play()
            time.sleep(0.1)
            resp = self.switch_desktop()
            return f"CMD_SWITCH_DESKTOP sent, resp={'yes' if resp else 'none'}"

        elif strategy == 2:
            print(f"[{ts}] Strategy 2: stop + black JPEG via CMD_PUSH_JPG")
            from PIL import Image
            self.stop_play()
            time.sleep(0.3)
            # Small black JPEG -- should be well under 2KB
            img = Image.new('RGB', (WIDTH, HEIGHT), (0, 0, 0))
            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=1)
            jpg_data = buf.getvalue()
            print(f"  JPEG size: {len(jpg_data)} bytes")
            resp = self.push_image(jpg_data, CMD_PUSH_JPG)
            return f"CMD_PUSH_JPG sent ({len(jpg_data)}B), resp={'yes' if resp else 'none'}"

        elif strategy == 3:
            print(f"[{ts}] Strategy 3: stop + black H.264 single I-frame")
            self.stop_play()
            time.sleep(0.3)
            from .content import generate_solid_h264
            h264 = generate_solid_h264('black', duration=1, fps=1)
            size = os.path.getsize(h264)
            print(f"  H.264 size: {size} bytes")
            self.play_h264(h264, loop=False)
            os.unlink(h264)
            self.stop_play()
            return f"Black H.264 streamed ({size}B) and stopped"

        elif strategy == 4:
            print(f"[{ts}] Strategy 4: stop + JPG background + PNG overlay")
            from PIL import Image
            self.stop_play()
            time.sleep(0.3)
            img = Image.new('RGB', (WIDTH, HEIGHT), (0, 0, 0))
            # JPG background layer
            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=1)
            self.push_image(buf.getvalue(), CMD_PUSH_JPG)
            time.sleep(0.1)
            # Opaque black PNG overlay
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            self.push_image(buf.getvalue(), CMD_PUSH_PNG)
            time.sleep(0.1)
            self.stop_play()
            return "JPG + PNG layers sent, stop_play sent"

        elif strategy == 5:
            print(f"[{ts}] Strategy 5: CMD_REBOOT (device returns to desktop mode)")
            resp = self.reboot()
            return f"CMD_REBOOT sent, resp={'yes' if resp else 'none'} -- device will need 'linx wake'"

        elif strategy == 6:
            # Full reinit matching lian-li-linux (sgtaziz/lian-li-linux)
            print(f"[{ts}] Strategy 6: full reinit (lian-li-linux sequence)")
            from PIL import Image
            self._flush_read()
            print("  StopPlay...")
            self.stop_play()
            time.sleep(0.1)
            print("  GetVer (state reset)...")
            self.get_version()
            print("  SyncClock + StopClock...")
            self.sync_clock(mode=2)
            self.stop_clock()
            # Transparent PNG to overlay layer
            print("  Push transparent PNG (overlay)...")
            img = Image.new('RGBA', (WIDTH, HEIGHT), (0, 0, 0, 0))
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            self.push_image(buf.getvalue(), CMD_PUSH_PNG)
            # Black JPEG to background layer (covers H.264 framebuffer)
            print("  Push black JPEG (background)...")
            img = Image.new('RGB', (WIDTH, HEIGHT), (0, 0, 0))
            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=1)
            jpg_data = buf.getvalue()
            print(f"  JPEG size: {len(jpg_data)} bytes")
            self.push_image(jpg_data, CMD_PUSH_JPG)
            print("  SetFrameRate(30)...")
            self.set_framerate(30)
            return f"Full reinit complete (JPG={len(jpg_data)}B)"

        return f"Unknown strategy: {strategy}"

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

        cmd=CMD_PUSH_PNG (102) for PNG layer (transparent overlay).
        cmd=CMD_PUSH_JPG (101) for JPG layer (opaque background, covers H.264).
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

        The JPG background layer covers the H.264 decoder framebuffer,
        so it must be an actual JPEG sent via CMD_PUSH_JPG to clear
        frozen video frames.
        """
        from PIL import Image
        # Clear PNG overlay (fully transparent)
        img = Image.new('RGBA', (WIDTH, HEIGHT), (0, 0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        self.push_image(buf.getvalue(), CMD_PUSH_PNG)
        # Clear JPG background (opaque black JPEG covers H.264 framebuffer)
        img = Image.new('RGB', (WIDTH, HEIGHT), (0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=85)
        self.push_image(buf.getvalue(), CMD_PUSH_JPG)

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
        print(f"[{time.strftime('%H:%M:%S')}] Warning: buffer wait timeout")

    def request_stop(self):
        """Request playback stop from another thread (GUI-safe)."""
        self._stop = True

    def play_h264(self, filepath, loop=True, play_cmd=CMD_START_PLAY, play_count=1):
        """Stream raw H.264 file to the device.

        Reads in h264_buf_len chunks, sends each with an encrypted header.
        30ms delay between chunks. Flow control via QueryBlock polling.
        Ctrl+C / SIGTERM / request_stop() to stop.
        """
        if not os.path.exists(filepath):
            print(f"File not found: {filepath}")
            return False

        self._stop = False
        self.check_h264_block()
        buf_len = self.h264_buf_len
        buf_idx = {CMD_START_PLAY: 8, CMD_START_PLAY1: 9, CMD_START_PLAY2: 10}.get(play_cmd, 8)

        try:
            while not self._stop:
                with open(filepath, 'rb') as f:
                    while not self._stop:
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
                        buf[0:512] = make_header(play_cmd, header_data)
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
        try:
            self.dev.set_configuration()
        except usb.core.USBError:
            pass
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
