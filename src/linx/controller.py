# device controller -- single owner of the lcd + led handles and their lifecycle
#
# centralizes what used to be scattered across widgets: threaded connect /
# disconnect, off-thread device ops with consistent error reporting, and a
# poll-based hotplug watch that tears the UI down cleanly on unplug.

import subprocess
import threading

import usb.core
from gi.repository import GLib

from .device import LCDDevice, LEDDevice
from .log import get_logger
from .protocol import LCD_PID, LCD_VID

log = get_logger(__name__)

NIXIE_SERVICE = 'nixie-clock.service'
WATCH_INTERVAL_MS = 2000


class DeviceController:
    def __init__(self, window):
        self.window = window
        self.lcd = None
        self.led = None
        self._watch_id = None

    # ---==<connection>==---

    def connect_async(self, on_result):
        """connect to lcd + led off the UI thread; on_result(lcd, led, fw, led_ver)
        is invoked on the UI thread when done."""
        def _work():
            # a running nixie-clock service would be holding the usb device
            try:
                subprocess.run(['systemctl', '--user', 'stop', NIXIE_SERVICE],
                               capture_output=True, text=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                pass

            lcd, fw = None, None
            try:
                lcd = LCDDevice()
                if lcd.connect():
                    fw = lcd.get_version()
                else:
                    lcd = None
            except Exception as e:
                log.warning("lcd connect failed: %s", e)
                lcd = None

            led, led_ver = None, None
            try:
                led = LEDDevice()
                if led.connect():
                    led_ver = led.get_version()
                else:
                    led = None
            except Exception as e:
                log.warning("led connect failed: %s", e)
                led = None

            self.lcd, self.led = lcd, led
            GLib.idle_add(on_result, lcd, led, fw, led_ver)

        threading.Thread(target=_work, daemon=True).start()

    def disconnect(self, leds_off=True):
        """release both devices. leds_off=False when the device is already gone."""
        if self.lcd:
            try:
                self.lcd.close()
            except Exception as e:
                log.debug("lcd close: %s", e)
            self.lcd = None
        if self.led:
            try:
                if leds_off:
                    self.led.off()
                self.led.close()
            except Exception as e:
                log.debug("led close: %s", e)
            self.led = None

    # ---==<off-thread ops>==---

    def run_op(self, fn, on_done=None, on_error=None, error_prefix=''):
        """run a blocking device call off the UI thread, reporting errors as toasts."""
        def _work():
            try:
                result = fn()
            except Exception as e:
                log.debug("device op failed: %s", e)
                msg = f'{error_prefix}{e}' if error_prefix else str(e)
                GLib.idle_add(on_error or self.window.show_toast, msg)
                return
            if on_done:
                GLib.idle_add(on_done, result)
        threading.Thread(target=_work, daemon=True).start()

    # ---==<hotplug watch>==---

    def start_watch(self):
        if self._watch_id is None:
            self._watch_id = GLib.timeout_add(WATCH_INTERVAL_MS, self._poll)

    def stop_watch(self):
        if self._watch_id is not None:
            GLib.source_remove(self._watch_id)
            self._watch_id = None

    def _poll(self):
        # only react to losing a screen we currently hold -- a lightweight
        # usb scan is cheap and avoids a pyudev dependency
        if self.lcd and self.lcd.dev:
            if usb.core.find(idVendor=LCD_VID, idProduct=LCD_PID) is None:
                log.info("screen unplugged -- releasing handles")
                self.disconnect(leds_off=False)
                self.window.status_group.mark_disconnected()
                self.window.show_toast('Screen disconnected')
        return True  # keep polling
