import time

import usb.core
import usb.util

from . import constants as C
from .log import get_logger
from .protocol import HID_PID, HID_VID, LCD_PID, LCD_VID, MONITOR_MODE_CMD

log = get_logger(__name__)


def wake_from_desktop():
    """send SetMonitorMode to the WCH HID to wake the TI MCU -- returns True on success"""
    hid = usb.core.find(idVendor=HID_VID, idProduct=HID_PID)
    if hid is None:
        log.debug("wake: no HID (desktop-mode) device on the bus")
        return False
    try:
        if hid.is_kernel_driver_active(1):
            hid.detach_kernel_driver(1)
    except usb.core.USBError as e:
        log.debug("wake: detach_kernel_driver failed (continuing): %s", e)
    try:
        hid.set_configuration()
    except usb.core.USBError as e:
        log.debug("wake: set_configuration failed (continuing): %s", e)
    usb.util.claim_interface(hid, 1)
    pkt = bytearray(512)
    pkt[:len(MONITOR_MODE_CMD)] = MONITOR_MODE_CMD
    try:
        hid.write(0x02, bytes(pkt), timeout=C.READ_RESP_MS)
        log.info("SetMonitorMode sent, waiting for the TI MCU to enumerate")
    except usb.core.USBError as e:
        log.warning("wake: SetMonitorMode write failed: %s", e)
    usb.util.release_interface(hid, 1)

    for _ in range(C.WAKE_POLL_COUNT):
        time.sleep(C.WAKE_POLL_S)
        if usb.core.find(idVendor=LCD_VID, idProduct=LCD_PID):
            return True
    return False
