"""Connection status and device info."""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib

import threading
import usb.core

from ..protocol import LCD_VID, LCD_PID, HID_VID, HID_PID, LED_VID, LED_PID


class StatusGroup(Adw.PreferencesGroup):
    """Device connection status, firmware version, connect/disconnect."""

    def __init__(self, window):
        super().__init__(title='Device')
        self.window = window

        # -- Connection row --
        self.conn_row = Adw.ActionRow(title='Connection', subtitle='Disconnected')
        self.conn_icon = Gtk.Image.new_from_icon_name('network-offline-symbolic')
        self.conn_row.add_prefix(self.conn_icon)

        self.connect_btn = Gtk.Button(label='Connect', valign=Gtk.Align.CENTER)
        self.connect_btn.add_css_class('suggested-action')
        self.connect_btn.connect('clicked', self._on_connect)
        self.conn_row.add_suffix(self.connect_btn)
        self.add(self.conn_row)

        # -- Firmware row --
        self.fw_row = Adw.ActionRow(title='Firmware', subtitle='--')
        self.add(self.fw_row)

        # -- LED row --
        self.led_row = Adw.ActionRow(title='LED Ring', subtitle='--')
        self.add(self.led_row)

    def _on_connect(self, btn):
        if self.window.lcd and self.window.lcd.dev:
            self._disconnect()
        else:
            self._connect()

    def _connect(self):
        self.connect_btn.set_sensitive(False)
        self.conn_row.set_subtitle('Connecting...')

        def _work():
            from ..device import LCDDevice, LEDDevice
            lcd, led, fw, led_ver = None, None, None, None
            try:
                lcd = LCDDevice()
                lcd_ok = lcd.connect()
                if lcd_ok:
                    fw = lcd.get_version()
                else:
                    lcd = None
            except Exception as e:
                GLib.idle_add(self.window.show_toast, f'LCD: {e}')
                lcd = None

            try:
                led = LEDDevice()
                led_ok = led.connect()
                if led_ok:
                    led_ver = led.get_version()
                else:
                    led = None
            except Exception as e:
                GLib.idle_add(self.window.show_toast, f'LED: {e}')
                led = None

            GLib.idle_add(self._connect_done, lcd, led, fw, led_ver)

        threading.Thread(target=_work, daemon=True).start()

    def _connect_done(self, lcd, led, fw, led_ver):
        self.window.lcd = lcd
        self.window.led = led

        if lcd:
            self.conn_row.set_subtitle('Connected')
            self.conn_icon.set_from_icon_name('network-transmit-symbolic')
            self.connect_btn.set_label('Disconnect')
            self.connect_btn.remove_css_class('suggested-action')
            self.connect_btn.add_css_class('destructive-action')
            self.fw_row.set_subtitle(fw or 'unknown')
        else:
            self.conn_row.set_subtitle('Not found')
            self.conn_icon.set_from_icon_name('network-offline-symbolic')
            self.window.show_toast('LCD not found -- is the device plugged in?')

        if led:
            self.led_row.set_subtitle(f'Connected (v{led_ver})' if led_ver else 'Connected')
        else:
            self.led_row.set_subtitle('Not found')

        self.connect_btn.set_sensitive(True)
        self.window.on_connection_changed()

    def _disconnect(self):
        if self.window.lcd:
            self.window.lcd.close()
            self.window.lcd = None
        if self.window.led:
            self.window.led.off()
            self.window.led.close()
            self.window.led = None

        self.conn_row.set_subtitle('Disconnected')
        self.conn_icon.set_from_icon_name('network-offline-symbolic')
        self.connect_btn.set_label('Connect')
        self.connect_btn.remove_css_class('destructive-action')
        self.connect_btn.add_css_class('suggested-action')
        self.fw_row.set_subtitle('--')
        self.led_row.set_subtitle('--')
        self.window.on_connection_changed()
