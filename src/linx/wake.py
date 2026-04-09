import time
import usb.core
import usb.util

from .protocol import HID_VID, HID_PID, LCD_VID, LCD_PID, MONITOR_MODE_CMD


def wake_from_desktop():
    """send SetMonitorMode to WCH HID to wake the TI MCU -- returns True on success"""
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
    pkt[:len(MONITOR_MODE_CMD)] = MONITOR_MODE_CMD
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
