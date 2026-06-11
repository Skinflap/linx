# usb protocol constants, encryption, and packet construction
#
# des-cbc encrypted bulk transfers -- key and IV are both "slv3tuzx"
# each command is a 512-byte packet: 500-byte plaintext buffer, encrypted,
# padded to 512 bytes with a [0xA1, 0x1A] trailer
#
# reverse-engineered from lianli.lcd207.dll (L-Connect 3)

import struct
import time

from Crypto.Cipher import DES

# --<|||constants|||>--

# usb device IDs
LCD_VID, LCD_PID = 0x1CBE, 0xA088   # TI MCU -- monitor mode (display commands)
HID_VID, HID_PID = 0x1A86, 0xAD21   # WCH chip -- desktop/standby mode
LED_VID, LED_PID = 0x0416, 0x8050   # WCH chip -- LED ring controller
HUB_VID, HUB_PID = 0x1A86, 0x8091   # QinHeng chip -- screen's internal usb hub

# display resolution -- 8.8" portrait panel
WIDTH = 480
HEIGHT = 1920

# des-cbc -- key and IV are the same, because of course they are
DES_KEY = b'slv3tuzx'

# SetMonitorMode magic: ASCII "5f3759df" (the fast inverse sqrt constant lmao)
MONITOR_MODE_CMD = bytes([53, 102, 51, 55, 53, 57, 100, 102])

# ---==<command IDs>==---
# CmdType enum from lcd207.dll
CMD_GET_VER        = 10
CMD_REBOOT         = 11   # drops to desktop mode -- careful
CMD_ROTATE         = 13
CMD_BRIGHTNESS     = 14
CMD_SET_FRAMERATE  = 15
CMD_GET_H264_BLOCK = 17
CMD_UPDATE_FIRMWARE = 40
CMD_DEL_FILE       = 42
CMD_SET_CLOCK      = 51
CMD_STOP_CLOCK     = 52
# UNVERIFIED -- present in the decompiled enum but never exercised against
# hardware (these target aio-pump variants of the controller, not the 8.8"
# screen). kept for reference; do not rely on them.
CMD_GET_TEMPERATURE = 96
CMD_SET_PUMP_SPEED = 97
CMD_GET_PUMP_SPEED = 98
CMD_QUERY_DIR      = 99
CMD_PUSH_JPG       = 101  # jpg layer (opaque background, covers h264 framebuffer)
CMD_PUSH_PNG       = 102  # png layer (transparent overlay)
CMD_START_PLAY1    = 119  # h264 stream slot 1
CMD_START_PLAY2    = 120  # h264 stream slot 2
CMD_START_PLAY     = 121  # h264 stream slot 0 (primary)
CMD_QUERY_BLOCK    = 122
CMD_STOP_PLAY      = 123
CMD_SWITCH_DESKTOP = 150

# ---==<led colors>==---
LED_COLORS = {
    'off': (0, 0, 0), 'red': (255, 0, 0), 'green': (0, 255, 0),
    'blue': (0, 0, 255), 'white': (255, 255, 255), 'cyan': (0, 255, 255),
    'magenta': (255, 0, 255), 'yellow': (255, 255, 0),
    'charcoal': (0x8a, 0x92, 0xa4),
}

_start_time = time.time()


# --<|||encryption|||>--

def _ts():
    """ms since process start, 32-bit unsigned"""
    return int((time.time() - _start_time) * 1000) & 0xFFFFFFFF


def des_encrypt(data):
    """des-cbc with pkcs7 padding -- key = iv = 'slv3tuzx'"""
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv=DES_KEY)
    pad_len = 8 - (len(data) % 8)
    return cipher.encrypt(bytes(data) + bytes([pad_len] * pad_len))


def make_header(cmd, data_at_8=None):
    """build 512-byte encrypted command header

    GetBaseCmdBuf: buf[0]=cmd, buf[2]=0x1A, buf[3]=0x6D, buf[4:8]=timestamp(LE)
    encrypt 500 bytes -> copy into 512-byte packet -> trailer [0xA1, 0x1A]
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
    encrypted = des_encrypt(buf)
    packet = bytearray(512)
    packet[:len(encrypted)] = encrypted[:512]
    packet[510] = 0xA1
    packet[511] = 0x1A
    return bytes(packet)
