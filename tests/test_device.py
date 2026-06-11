import pytest
import usb.core
import usb.util

from linx import device
from linx.errors import DeviceDisconnected


class FakeDev:
    """minimal stand-in for a pyusb Device used by LCDDevice"""

    def __init__(self, write_error=False, read_data=None):
        self.manufacturer = 'LIANLI'
        self.product = '8.8" Universal Screen-1.0'
        self.write_error = write_error
        self.read_data = read_data  # bytes for the response read, else timeout
        self.writes = []
        self._served = False
        self._wrote = False

    def is_kernel_driver_active(self, intf):
        return False

    def detach_kernel_driver(self, intf):
        pass

    def set_configuration(self):
        pass

    def write(self, ep, data, timeout=0):
        if self.write_error:
            raise usb.core.USBError('write failed')
        self.writes.append(bytes(data))
        self._wrote = True
        return len(data)

    def read(self, ep, size, timeout=0):
        # serve read_data only for the response read (after a write); the
        # pre-write flush drains and everything else times out
        if self.read_data is not None and self._wrote and not self._served:
            self._served = True
            return self.read_data
        raise usb.core.USBTimeoutError('no data')


@pytest.fixture(autouse=True)
def _stub_usbutil(monkeypatch):
    monkeypatch.setattr(usb.util, 'claim_interface', lambda d, i: None)
    monkeypatch.setattr(usb.util, 'release_interface', lambda d, i: None)
    monkeypatch.setattr(usb.util, 'dispose_resources', lambda d: None)


def _patch_find(monkeypatch, dev):
    monkeypatch.setattr(usb.core, 'find', lambda **kw: dev)


def test_connect_success(monkeypatch):
    fake = FakeDev()
    _patch_find(monkeypatch, fake)
    d = device.LCDDevice()
    assert d.connect() is True
    assert d.dev is fake


def test_connect_not_found(monkeypatch):
    _patch_find(monkeypatch, None)
    d = device.LCDDevice()
    assert d.connect() is False


def test_connect_busy_returns_false(monkeypatch):
    fake = FakeDev()
    _patch_find(monkeypatch, fake)

    def busy(dev, intf):
        raise usb.core.USBError('resource busy')
    monkeypatch.setattr(usb.util, 'claim_interface', busy)

    d = device.LCDDevice()
    assert d.connect() is False        # graceful, not a traceback
    assert d.dev is None


def test_stop_flag_is_event_backed():
    d = device.LCDDevice()
    assert d._stop is False
    d.request_stop()
    assert d._stop is True


def test_send_read_timeout_returns_none(monkeypatch):
    fake = FakeDev()  # writes ok, reads always time out
    _patch_find(monkeypatch, fake)
    d = device.LCDDevice()
    d.connect()
    assert d._send_and_read(b'x' * 16) is None


def test_send_disconnect_raises(monkeypatch):
    fake = FakeDev(write_error=True)  # every write fails, reconnect finds the same dead dev
    _patch_find(monkeypatch, fake)
    d = device.LCDDevice()
    d.dev = fake  # pretend already connected
    with pytest.raises(DeviceDisconnected):
        d._send_and_read(b'x' * 16)


def test_check_h264_block_rejects_implausible_size(monkeypatch):
    # device reports a 1 GB buffer -> keep the safe default, don't trust it
    big = bytes(8) + (0x40000000).to_bytes(4, 'big') + bytes(4)
    fake = FakeDev(read_data=big)
    _patch_find(monkeypatch, fake)
    d = device.LCDDevice()
    d.connect()
    assert d.check_h264_block() == device.C.DEFAULT_H264_BUF_LEN
