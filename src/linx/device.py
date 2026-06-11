import datetime
import io
import os
import threading
import time

import usb.core
import usb.util

from . import constants as C
from .errors import DeviceDisconnected
from .log import get_logger
from .protocol import (
    CMD_BRIGHTNESS,
    CMD_GET_H264_BLOCK,
    CMD_GET_VER,
    CMD_PUSH_JPG,
    CMD_PUSH_PNG,
    CMD_QUERY_BLOCK,
    CMD_REBOOT,
    CMD_ROTATE,
    CMD_SET_CLOCK,
    CMD_SET_FRAMERATE,
    CMD_START_PLAY,
    CMD_START_PLAY1,
    CMD_START_PLAY2,
    CMD_STOP_CLOCK,
    CMD_STOP_PLAY,
    CMD_SWITCH_DESKTOP,
    CMD_UPDATE_FIRMWARE,
    HEIGHT,
    HID_PID,
    HID_VID,
    HUB_PID,
    HUB_VID,
    LCD_PID,
    LCD_VID,
    LED_PID,
    LED_VID,
    WIDTH,
    make_header,
)
from .wake import wake_from_desktop

log = get_logger(__name__)

# --<|||diagnostics|||>--

# the screen is an internal usb hub (HUB_VID:HUB_PID) with the lcd controller
# and the led ring hanging off it. when the panel controller hangs it fails
# usb enumeration outright (kernel logs descriptor-read errors -110/-71) while
# the hub and led ring still come up. so "led/hub present but lcd absent" means
# the screen is plugged in and powered but the display silicon isn't answering
# the host -- no software reset recovers this, only a physical power-cycle.

def diagnose():
    """classify why the lcd is unreachable -- returns (code, message)"""
    if usb.core.find(idVendor=LCD_VID, idProduct=LCD_PID) is not None:
        return 'ok', 'lcd present in monitor mode'
    if usb.core.find(idVendor=HID_VID, idProduct=HID_PID) is not None:
        return 'desktop', 'screen is in desktop mode -- run `linx wake` to switch to monitor mode'
    screen_present = (
        usb.core.find(idVendor=LED_VID, idProduct=LED_PID) is not None
        or usb.core.find(idVendor=HUB_VID, idProduct=HUB_PID) is not None
    )
    if screen_present:
        return 'controller_dead', (
            'screen is connected (led ring/hub enumerated) but the display '
            'controller is not responding on usb -- power-cycle the screen '
            '(check its SATA power lead). a reboot or software reset will not fix this'
        )
    return 'absent', 'no screen detected on usb -- check the data and power cables'


# --<|||lcd controller|||>--

class LCDDevice:
    """des-encrypted usb bulk transfers to the 8.8" lcd"""

    def __init__(self):
        self.dev = None
        self.h264_buf_len = C.DEFAULT_H264_BUF_LEN  # queried from device before streaming
        self._stop_event = threading.Event()
        self._keep_display = False

    @property
    def _stop(self):
        """read-only view of the stop flag -- set via request_stop()"""
        return self._stop_event.is_set()

    # ---==<connection>==---

    def connect(self):
        """find and claim the usb device, auto-wakes from desktop mode"""
        self.dev = usb.core.find(idVendor=LCD_VID, idProduct=LCD_PID)
        if self.dev is None:
            if usb.core.find(idVendor=HID_VID, idProduct=HID_PID):
                log.info("device in desktop mode, switching to monitor mode")
                if wake_from_desktop():
                    self.dev = usb.core.find(idVendor=LCD_VID, idProduct=LCD_PID)
        if self.dev is None:
            return False
        try:
            self._claim()
        except usb.core.USBError as e:
            log.warning("could not claim lcd interface: %s -- the device is busy "
                        "(another linx process/GUI may hold it) or udev permissions "
                        "are missing", e)
            self.dev = None
            return False
        try:
            log.info("connected: %s %s", self.dev.manufacturer, self.dev.product)
        except (ValueError, usb.core.USBError):
            log.info("connected: %04x:%04x", LCD_VID, LCD_PID)
        return True

    def _claim(self):
        """detach any kernel driver, set config, claim interface 0"""
        try:
            if self.dev.is_kernel_driver_active(0):
                self.dev.detach_kernel_driver(0)
        except usb.core.USBError as e:
            log.debug("detach_kernel_driver failed (continuing): %s", e)
        try:
            self.dev.set_configuration()
        except usb.core.USBError as e:
            log.debug("set_configuration failed (continuing): %s", e)
        usb.util.claim_interface(self.dev, 0)

    def close(self):
        if self.dev:
            try:
                usb.util.release_interface(self.dev, 0)
            except usb.core.USBError as e:
                log.debug("release_interface failed: %s", e)
            self.dev = None

    def _reconnect(self):
        # <[|matches ReInitDev from decompiled source|]>
        try:
            usb.util.release_interface(self.dev, 0)
        except usb.core.USBError as e:
            log.debug("release_interface during reconnect failed: %s", e)
        try:
            usb.util.dispose_resources(self.dev)
        except usb.core.USBError as e:
            log.debug("dispose_resources during reconnect failed: %s", e)
        self.dev = None
        time.sleep(0.1)
        self.dev = usb.core.find(idVendor=LCD_VID, idProduct=LCD_PID)
        if self.dev is None:
            log.debug("reconnect: device not found on bus")
            return False
        try:
            self._claim()
        except usb.core.USBError as e:
            log.debug("reconnect: claim failed: %s", e)
            self.dev = None
            return False
        log.debug("reconnect: re-acquired device")
        return True

    # ---==<low-level i/o>==---

    def _flush_read(self):
        """drain stale data from read endpoint"""
        while True:
            try:
                self.dev.read(C.EP_IN, 512, timeout=C.READ_FLUSH_MS)
            except (usb.core.USBTimeoutError, usb.core.USBError):
                break

    def _send_and_read(self, data, read=True):
        """write data, optionally read response.

        a write failure is treated as a possible disconnect: reconnect once and
        retry. if that also fails the device is genuinely gone -> raise
        DeviceDisconnected so the caller stops instead of spinning. a missing
        *response* (read timeout) is benign for many commands and returns None.
        """
        self._flush_read()
        write_ms = max(C.WRITE_BASE_MS, len(data) // C.WRITE_PER_BYTES + C.WRITE_BASE_MS)
        try:
            self.dev.write(C.EP_OUT, data, timeout=write_ms)
        except usb.core.USBError as e:
            log.debug("write failed (%s), attempting reconnect", e)
            if not self._reconnect():
                raise DeviceDisconnected("write failed and device did not re-enumerate") from e
            try:
                self.dev.write(C.EP_OUT, data, timeout=write_ms)
            except usb.core.USBError as e2:
                raise DeviceDisconnected("write failed again after reconnect") from e2
        if not read:
            return b''
        try:
            resp = bytes(self.dev.read(C.EP_IN, 512, timeout=C.READ_RESP_MS))
            self._flush_read()
            return resp
        except usb.core.USBTimeoutError:
            return None  # no response is expected for some commands
        except usb.core.USBError as e:
            log.debug("read failed: %s", e)
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
        """query the device's preferred chunk size, validated against a sane ceiling"""
        resp = self.send_cmd(CMD_GET_H264_BLOCK)
        if resp and len(resp) > 11:
            size = (resp[8] << 24) | (resp[9] << 16) | (resp[10] << 8) | resp[11]
            if 0 < size <= C.MAX_H264_BUF_LEN:
                self.h264_buf_len = size
                return size
            if size > C.MAX_H264_BUF_LEN:
                log.warning("device reported implausible h264 buffer %d, keeping %d",
                            size, self.h264_buf_len)
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

    _BLOCK_IDX = {CMD_START_PLAY: 8, CMD_START_PLAY1: 9, CMD_START_PLAY2: 10}

    def _wait_buffer(self, max_blocks=C.BUFFER_TARGET_BLOCKS, play_cmd=CMD_START_PLAY):
        """poll QueryBlock until the device buffer drains to max_blocks (or give up)"""
        buf_idx = self._BLOCK_IDX.get(play_cmd, 8)
        for _ in range(C.BUFFER_POLL_MAX):
            if self._stop_event.wait(C.BUFFER_POLL_S):
                return  # stop requested
            resp = self.send_cmd(CMD_QUERY_BLOCK)
            if resp and len(resp) > buf_idx and resp[buf_idx] <= max_blocks:
                return
        log.warning("buffer wait timed out after %d polls", C.BUFFER_POLL_MAX)

    def request_stop(self):
        """signal any running play_h264 loop to stop -- safe to call from any thread"""
        self._stop_event.set()

    def play_h264(self, filepath, loop=True, play_cmd=CMD_START_PLAY, play_count=1):
        """stream raw h264 to the device in chunks with flow control.

        returns True on a clean finish/stop, False if the file is missing.
        raises DeviceDisconnected if the device falls off the bus mid-stream.
        """
        if not os.path.exists(filepath):
            log.error("file not found: %s", filepath)
            return False

        self._stop_event.clear()
        self.check_h264_block()
        buf_len = self.h264_buf_len
        buf_idx = self._BLOCK_IDX.get(play_cmd, 8)

        try:
            while not self._stop_event.is_set():
                with open(filepath, 'rb') as f:
                    while not self._stop_event.is_set():
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
                        time.sleep(C.CHUNK_DELAY_S)
                        if resp and len(resp) > buf_idx and resp[buf_idx] > C.BUFFER_BUSY_BLOCKS:
                            self._wait_buffer(C.BUFFER_TARGET_BLOCKS, play_cmd)

                if not loop:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            if not self._keep_display:
                try:
                    self.stop_play()
                except DeviceDisconnected:
                    log.debug("stop_play skipped -- device already gone")
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
        try:
            if self.dev.is_kernel_driver_active(0):
                self.dev.detach_kernel_driver(0)
        except usb.core.USBError as e:
            log.debug("led detach_kernel_driver failed (continuing): %s", e)
        try:
            self.dev.set_configuration()
        except usb.core.USBError as e:
            log.debug("led set_configuration failed (continuing): %s", e)
        try:
            usb.util.claim_interface(self.dev, 0)
        except usb.core.USBError as e:
            log.warning("could not claim led interface: %s (busy or permissions)", e)
            self.dev = None
            return False
        return True

    def close(self):
        if self.dev:
            try:
                usb.util.release_interface(self.dev, 0)
            except usb.core.USBError as e:
                log.debug("led release_interface failed: %s", e)
            self.dev = None

    def _send(self, data, read=True):
        # fire-and-forget: a dead led ring must never crash a caller (e.g. off()
        # in a cleanup path), so write errors are logged and swallowed.
        buf = bytearray(64)
        buf[:min(len(data), 64)] = data[:64]
        try:
            self.dev.write(C.EP_OUT, bytes(buf), timeout=C.LED_WRITE_MS)
        except usb.core.USBError as e:
            log.debug("led write failed: %s", e)
            return None
        if not read:
            return None
        try:
            return bytes(self.dev.read(C.EP_IN, 64, timeout=C.LED_READ_MS))
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
