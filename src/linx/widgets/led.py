"""LED ring controls -- color picker, ambilight, grayscale."""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gdk


class LEDGroup(Adw.PreferencesGroup):
    """LED ring color, ambilight toggle, grayscale max."""

    def __init__(self, window):
        super().__init__(title='LED Ring')
        self.window = window

        # -- Color picker --
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

        # -- Ambilight toggle --
        self.ambilight_row = Adw.SwitchRow(title='Ambilight',
                                            subtitle='Sync LEDs to screen edges during playback')
        self.add(self.ambilight_row)

        # -- Grayscale max --
        self.grayscale_row = Adw.SpinRow.new_with_range(0, 255, 1)
        self.grayscale_row.set_title('Grayscale max')
        self.grayscale_row.set_subtitle('0 = full color, 1-255 = grayscale brightness cap')
        self.grayscale_row.set_value(0)
        self.add(self.grayscale_row)

    def _get_rgb(self):
        rgba = self.color_btn.get_rgba()
        return (int(rgba.red * 255), int(rgba.green * 255), int(rgba.blue * 255))

    def _on_apply(self, btn):
        led = self.window.led
        if not led or not led.dev:
            self.window.show_toast('LED device not connected')
            return
        r, g, b = self._get_rgb()
        led.set_all(r, g, b)

    def _on_off(self, btn):
        led = self.window.led
        if not led or not led.dev:
            self.window.show_toast('LED device not connected')
            return
        led.off()

    def set_sensitive_all(self, sensitive):
        """Enable/disable based on LED connection."""
        self.apply_btn.set_sensitive(sensitive)
        self.off_btn.set_sensitive(sensitive)
