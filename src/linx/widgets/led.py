# led ring controls -- color, brightness, ambilight

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gdk


class LEDGroup(Adw.PreferencesGroup):

    def __init__(self, window):
        super().__init__(title='LED Ring')
        self.window = window

        # -- color picker --
        self.color_row = Adw.ActionRow(title='Color')
        self._rgba = Gdk.RGBA()
        self._rgba.parse('red')

        self.color_btn = Gtk.ColorDialogButton(
            dialog=Gtk.ColorDialog(title='LED Color'),
            rgba=self._rgba,
            valign=Gtk.Align.CENTER,
        )
        self.color_row.add_suffix(self.color_btn)

        self.apply_btn = Gtk.Button(label='Apply', valign=Gtk.Align.CENTER)
        self.apply_btn.add_css_class('suggested-action')
        self.apply_btn.connect('clicked', self._on_apply)
        self.color_row.add_suffix(self.apply_btn)

        self.off_btn = Gtk.Button(label='Off', valign=Gtk.Align.CENTER)
        self.off_btn.connect('clicked', self._on_off)
        self.color_row.add_suffix(self.off_btn)
        self.add(self.color_row)

        # -- brightness --
        self.brightness_row = Adw.ActionRow(title='LED Brightness')
        self.brightness_scale = Gtk.Scale.new_with_range(
            Gtk.Orientation.HORIZONTAL, 0, 100, 1)
        self.brightness_scale.set_value(100)
        self.brightness_scale.set_hexpand(True)
        self.brightness_scale.set_valign(Gtk.Align.CENTER)
        self.brightness_scale.set_size_request(200, -1)
        self.brightness_row.add_suffix(self.brightness_scale)
        self.add(self.brightness_row)

        # -- ambilight toggle --
        self.ambilight_row = Adw.SwitchRow(title='Ambilight',
                                            subtitle='Sync LEDs to screen edges during playback')
        self.add(self.ambilight_row)

    def get_brightness(self):
        """0.0 - 1.0 brightness scalar"""
        return self.brightness_scale.get_value() / 100.0

    def _get_rgb(self):
        rgba = self.color_btn.get_rgba()
        return (int(rgba.red * 255), int(rgba.green * 255), int(rgba.blue * 255))

    def _on_apply(self, btn):
        led = self.window.led
        if not led or not led.dev:
            self.window.show_toast('LED device not connected')
            return
        r, g, b = self._get_rgb()
        bri = self.get_brightness()
        led.set_all(int(r * bri), int(g * bri), int(b * bri))

    def _on_off(self, btn):
        led = self.window.led
        if not led or not led.dev:
            return
        led.off()

    def set_sensitive_all(self, sensitive):
        self.apply_btn.set_sensitive(sensitive)
        self.off_btn.set_sensitive(sensitive)
