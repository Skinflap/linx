"""Linx GUI -- GTK4 + libadwaita control panel for the Lian Li 8.8" screen."""

import sys

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib

from .widgets.status import StatusGroup
from .widgets.display import DisplayGroup
from .widgets.led import LEDGroup
from .widgets.service import ServiceGroup


class LinxWindow(Adw.ApplicationWindow):

    def __init__(self, app):
        super().__init__(application=app, title='Linx', default_width=480, default_height=720)
        self.lcd = None
        self.led = None

        # -- Layout --
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        toolbar.add_top_bar(header)

        self.toast_overlay = Adw.ToastOverlay()
        toolbar.set_content(self.toast_overlay)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        self.toast_overlay.set_child(scroll)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        scroll.set_child(box)

        # -- Widget groups --
        self.status_group = StatusGroup(self)
        box.append(self.status_group)

        self.display_group = DisplayGroup(self)
        box.append(self.display_group)

        self.led_group = LEDGroup(self)
        box.append(self.led_group)

        self.service_group = ServiceGroup(self)
        box.append(self.service_group)

        self.set_content(toolbar)

        # Start with display/led controls dimmed
        self.on_connection_changed()

    def on_connection_changed(self):
        """Called when device connection state changes."""
        lcd_ok = self.lcd is not None and self.lcd.dev is not None
        led_ok = self.led is not None and self.led.dev is not None
        self.display_group.set_sensitive_all(lcd_ok)
        self.led_group.set_sensitive_all(led_ok)

    def show_toast(self, message):
        toast = Adw.Toast(title=message, timeout=3)
        self.toast_overlay.add_toast(toast)

    def do_close_request(self):
        """Clean up devices on window close."""
        if self.lcd:
            if not self.lcd._stop and self.lcd.dev:
                self.lcd.request_stop()
            try:
                self.lcd.close()
            except Exception:
                pass
        if self.led:
            try:
                self.led.off()
                self.led.close()
            except Exception:
                pass
        return False  # allow close


class LinxApp(Adw.Application):

    def __init__(self):
        super().__init__(application_id='dev.linx.controller')

    def do_activate(self):
        win = LinxWindow(self)
        win.present()


def main():
    app = LinxApp()
    app.run(sys.argv)


if __name__ == '__main__':
    main()
