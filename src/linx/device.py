# usb device controllers for the lcd display and led ring

import datetime
import io
import os
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


# --<|||lcd controller|||>--

class LCDDevice:
    """des-encrypted usb bulk transfers to the 8.8" lcd"""

    def __init__(self):
        self.dev = None
        self.h264_buf_len = 202752  # queried from device before streaming
        self._stop = False

    # ---==<connection>==---

    def connect(self):
        """find and claim the usb device, auto-wakes from desktop mode"""
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
        if self.dev:
            try:
                usb.util.release_interface(self.dev, 0)
            except usb.core.USBError:
                pass
            self.dev = None

    def _reconnect(self):
        # <[|matches ReInitDev from decompiled source|]>
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

    # ---==<low-level i/o>==---

    def _flush_read(self):
        """drain stale data from read endpoint"""
        while True:
            try:
                self.dev.read(0x81, 512, timeout=10)
            except (usb.core.USBTimeoutError, usb.core.USBError):
                break

    def _send_and_read(self, data, read=True):
        """write data, optionally read response -- retries once on failure"""
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
        """send encrypted command, return response"""
        return self._send_and_read(make_header(cmd, data))

    def send_with_payload(self, cmd, payload, data_at_8=None):
        """encrypted header + raw payload as single usb transfer"""
        header = make_header(cmd, data_at_8)
        buf = bytearray(512 + len(payload))
        buf[0:512] = header
        buf[512:] = payload
        return self._send_and_read(bytes(buf))

    # ---==<display commands>==---

    def init(self):
        """matches WinUsbH2S.InitDev()"""
        self.set_framerate(30)

    def get_version(self):
        resp = self.send_cmd(CMD_GET_VER)
        if resp and len(resp) > 8:
            return resp[8:40].decode('ascii', errors='replace').rstrip('\x00')
        return None

    def set_brightness(self, level):
        return self.send_cmd(CMD_BRIGHTNESS, bytes([max(0, min(100, level))]))

    def set_rotation(self, rot):
        return self.send_cmd(CMD_ROTATE, bytes([rot & 0x03]))

    def set_framerate(self, fps):
        return self.send_cmd(CMD_SET_FRAMERATE, bytes([max(1, min(99, fps))]))

    def stop_play(self):
        return self.send_cmd(CMD_STOP_PLAY)

    def switch_desktop(self):
        """firmware-level desktop switch (cmd 150), not the physical HID mode switch"""
        return self.send_cmd(CMD_SWITCH_DESKTOP)

    def reboot(self):
        """drops back to desktop mode"""
        return self.send_cmd(CMD_REBOOT)

    def sync_clock(self, mode=2):
        """mode: 0=disable, 1=enable, 2=sync only"""
        now = datetime.datetime.now()
        data = bytes([
            (now.year >> 8) & 0xFF, now.year & 0xFF,
            now.month, now.day, now.hour, now.minute, now.second,
            mode & 0xFF
        ])
        return self.send_cmd(CMD_SET_CLOCK, data)

    def stop_clock(self):
        return self.send_cmd(CMD_STOP_CLOCK, bytes([0]))

    def query_block(self):
        return self.send_cmd(CMD_QUERY_BLOCK)

    def check_h264_block(self):
        resp = self.send_cmd(CMD_GET_H264_BLOCK)
        if resp and len(resp) > 11:
            size = (resp[8] << 24) | (resp[9] << 16) | (resp[10] << 8) | resp[11]
            if size > 0:
                self.h264_buf_len = size
                return size
        return self.h264_buf_len

    # ---==<image push>==---

    def push_image(self, image_bytes, cmd=CMD_PUSH_PNG):
        """CMD_PUSH_PNG (102) = transparent overlay, CMD_PUSH_JPG (101) = opaque background"""
        length = len(image_bytes)
        data = bytes([
            (length >> 24) & 0xFF, (length >> 16) & 0xFF,
            (length >> 8) & 0xFF, length & 0xFF
        ])
        return self.send_with_payload(cmd, image_bytes, data)

    def push_png(self, png_bytes):
        return self.push_image(png_bytes, CMD_PUSH_PNG)

    def clear_layers(self):
        """clear both display layers -- jpg background covers the h264 decoder framebuffer"""
        from PIL import Image
        # transparent png overlay
        img = Image.new('RGBA', (WIDTH, HEIGHT), (0, 0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        self.push_image(buf.getvalue(), CMD_PUSH_PNG)
        # opaque black jpeg background -- this is what actually kills the frozen h264 frame
        img = Image.new('RGB', (WIDTH, HEIGHT), (0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=85)
        self.push_image(buf.getvalue(), CMD_PUSH_JPG)

    def prepare_display(self):
        """full display prep matching ApplyTemplate"""
        self.sync_clock(mode=2)
        self.stop_clock()
        self.clear_layers()

    # ---==<h264 streaming>==---

    def _wait_buffer(self, max_blocks=2, play_cmd=CMD_START_PLAY):
        """poll QueryBlock until the device buffer has room"""
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
        print(f"[{time.strftime('%H:%M:%S')}] buffer wait timeout")

    def request_stop(self):
        """thread-safe stop flag for gui"""
        self._stop = True

    def play_h264(self, filepath, loop=True, play_cmd=CMD_START_PLAY, play_count=1):
        """stream raw h264 to the device in chunks with flow control"""
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

        self.stop_play()
        return True

    # ---==<file upload>==---

    def upload_file(self, data, target_path):
        """upload to device filesystem (e.g. /usr/data/boot.jpg)"""
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


# --<|||led ring|||>--

class LEDDevice:
    """60-led rgb ring (0416:8050) via raw HID packets -- fire and forget"""

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
        """3 groups of 20, 60 bytes rgb per group, fire-and-forget"""
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
        self.set_leds([(r, g, b)] * self.NUM_LEDS)

    def off(self):
        self.set_all(0, 0, 0)
