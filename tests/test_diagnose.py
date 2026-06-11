import usb.core

from linx import device
from linx.protocol import (
    HID_PID,
    HID_VID,
    HUB_PID,
    HUB_VID,
    LCD_PID,
    LCD_VID,
    LED_PID,
    LED_VID,
)


def _patch_present(monkeypatch, present):
    """make usb.core.find return a sentinel only for (vid, pid) pairs in `present`"""
    def fake_find(idVendor=None, idProduct=None, **kw):
        return object() if (idVendor, idProduct) in present else None
    monkeypatch.setattr(usb.core, 'find', fake_find)


def test_diagnose_ok(monkeypatch):
    _patch_present(monkeypatch, {(LCD_VID, LCD_PID)})
    assert device.diagnose()[0] == 'ok'


def test_diagnose_desktop_mode(monkeypatch):
    _patch_present(monkeypatch, {(HID_VID, HID_PID)})
    assert device.diagnose()[0] == 'desktop'


def test_diagnose_controller_dead(monkeypatch):
    # led ring / hub present but no lcd, no hid -> the real-world failure we hit
    _patch_present(monkeypatch, {(LED_VID, LED_PID), (HUB_VID, HUB_PID)})
    code, msg = device.diagnose()
    assert code == 'controller_dead'
    assert 'power-cycle' in msg


def test_diagnose_absent(monkeypatch):
    _patch_present(monkeypatch, set())
    assert device.diagnose()[0] == 'absent'
