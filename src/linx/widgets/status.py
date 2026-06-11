# connection status and device info

import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Adw, Gtk


class StatusGroup(Adw.PreferencesGroup):
    """device connection status and controls"""

    def __init__(self, window):
        super().__init__(title='Device')
        self.window = window

        # ---==<connection>==---
        self.conn_row = Adw.ActionRow(title='Connection', subtitle='Disconnected')
        self.conn_icon = Gtk.Image.new_from_icon_name('network-offline-symbolic')
        self.conn_row.add_prefix(self.conn_icon)

        self.connect_btn = Gtk.Button(label='Connect', valign=Gtk.Align.CENTER)
        self.connect_btn.add_css_class('suggested-action')
        self.connect_btn.connect('clicked', self._on_connect)
        self.conn_row.add_suffix(self.connect_btn)
        self.add(self.conn_row)

        # ---==<firmware>==---
        self.fw_row = Adw.ActionRow(title='Firmware', subtitle='--')
        self.add(self.fw_row)

        # ---==<led>==---
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
        # the controller owns the connect lifecycle (stops nixie, claims devices)
        self.window.controller.connect_async(self._connect_done)

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
            from ..device import diagnose
            code, msg = diagnose()
            self.conn_row.set_subtitle('Controller not responding' if code == 'controller_dead' else 'Not found')
            self.conn_icon.set_from_icon_name('network-offline-symbolic')
            self.window.show_toast(msg)

        if led:
            self.led_row.set_subtitle(f'Connected (v{led_ver})' if led_ver else 'Connected')
        else:
            self.led_row.set_subtitle('Not found')

        self.connect_btn.set_sensitive(True)
        self.window.on_connection_changed()

    def _disconnect(self):
        self.window.controller.disconnect()
        self.mark_disconnected()

    def mark_disconnected(self):
        # ui-only refresh -- caller has already released the devices
        self.conn_row.set_subtitle('Disconnected')
        self.conn_icon.set_from_icon_name('network-offline-symbolic')
        self.connect_btn.set_label('Connect')
        self.connect_btn.remove_css_class('destructive-action')
        self.connect_btn.add_css_class('suggested-action')
        self.fw_row.set_subtitle('--')
        self.led_row.set_subtitle('--')
        self.window.on_connection_changed()
