import sys

import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Adw, Gio, Gtk

from . import __version__
from .config import _deep_merge, load_config, save_config
from .controller import DeviceController
from .log import get_logger
from .widgets.display import DisplayGroup
from .widgets.led import LEDGroup
from .widgets.service import ServiceGroup
from .widgets.status import StatusGroup

log = get_logger(__name__)

APP_ID = 'dev.linx.controller'

_COLOR_SCHEMES = {
    'system': Adw.ColorScheme.DEFAULT,
    'light': Adw.ColorScheme.FORCE_LIGHT,
    'dark': Adw.ColorScheme.FORCE_DARK,
}


class LinxWindow(Adw.ApplicationWindow):

    def __init__(self, app):
        super().__init__(application=app, title='Linx')
        # the controller owns the device handles; window.lcd/window.led are
        # delegating properties so existing widget code keeps working unchanged
        self.controller = DeviceController(self)
        self._config = load_config()

        # restore window geometry (sensible portrait-ish default)
        gui_cfg = self._config.get('gui', {})
        self.set_default_size(gui_cfg.get('win_width', 480), gui_cfg.get('win_height', 760))

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.pack_end(self._build_menu_button())
        toolbar.add_top_bar(header)

        # disconnected empty-state prompt -- revealed when no screen is connected
        self.banner = Adw.Banner(title='No screen connected', button_label='Connect')
        self.banner.connect('button-clicked', lambda _b: self.status_group._on_connect(None))
        toolbar.add_top_bar(self.banner)

        self.toast_overlay = Adw.ToastOverlay()
        toolbar.set_content(self.toast_overlay)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        self.toast_overlay.set_child(scroll)

        clamp = Adw.Clamp(maximum_size=600, tightening_threshold=400)
        scroll.set_child(clamp)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        clamp.set_child(box)

        self.status_group = StatusGroup(self)
        box.append(self.status_group)

        self.display_group = DisplayGroup(self, config=self._config)
        box.append(self.display_group)

        self.led_group = LEDGroup(self)
        box.append(self.led_group)

        self.service_group = ServiceGroup(self)
        box.append(self.service_group)

        self.set_content(toolbar)
        self.on_connection_changed()

        # restore previous state after widgets are built
        self.display_group.restore_state()

        # watch for the screen being unplugged while connected
        self.controller.start_watch()

    # device handles live on the controller; expose them as the names widgets expect
    @property
    def lcd(self):
        return self.controller.lcd

    @lcd.setter
    def lcd(self, value):
        self.controller.lcd = value

    @property
    def led(self):
        return self.controller.led

    @led.setter
    def led(self, value):
        self.controller.led = value

    def _build_menu_button(self):
        menu = Gio.Menu()
        menu.append('Preferences', 'app.preferences')
        menu.append('Keyboard Shortcuts', 'app.shortcuts')
        menu.append('About Linx', 'app.about')
        menu.append('Quit', 'app.quit')

        button = Gtk.MenuButton(icon_name='open-menu-symbolic')
        button.set_tooltip_text('Main Menu')
        button.set_menu_model(menu)
        return button

    # ---==<device op helper>==---

    def run_device_op(self, fn, on_done=None, on_error=None, error_prefix=''):
        """run a blocking device call off the UI thread, reporting errors as toasts.

        keeps the UI responsive (USB calls take tens of ms) and gives every
        device action consistent feedback instead of silent fire-and-forget.
        """
        self.controller.run_op(fn, on_done, on_error, error_prefix)

    def on_connection_changed(self):
        lcd_ok = self.lcd is not None and self.lcd.dev is not None
        led_ok = self.led is not None and self.led.dev is not None
        self.display_group.set_sensitive_all(lcd_ok)
        self.led_group.set_sensitive_all(led_ok)
        self.banner.set_revealed(not lcd_ok)

    def show_toast(self, message):
        self.toast_overlay.add_toast(Adw.Toast(title=str(message), timeout=3))

    def apply_color_scheme(self, name):
        scheme = _COLOR_SCHEMES.get(name, Adw.ColorScheme.DEFAULT)
        Adw.StyleManager.get_default().set_color_scheme(scheme)

    def do_close_request(self):
        self.controller.stop_watch()
        # persist gui state + window geometry
        try:
            state = self.display_group.get_state()
            w, h = self.get_default_size()
            state.setdefault('gui', {})['win_width'] = w
            state['gui']['win_height'] = h
            save_config(_deep_merge(self._config, state))
        except Exception as e:
            log.warning("failed to save gui state: %s", e)

        # stop playback loop but keep content on screen
        if self.lcd:
            self.lcd._keep_display = True
            if not self.lcd._stop and self.lcd.dev:
                self.lcd.request_stop()

        # wait for play thread cleanup (terminates ffmpeg decoder)
        play_thread = self.display_group._play_thread
        if play_thread and play_thread.is_alive():
            play_thread.join(timeout=5)

        # release devices without clearing display or leds
        for dev in (self.lcd, self.led):
            if dev:
                try:
                    dev.close()
                except Exception as e:
                    log.debug("device close on exit failed: %s", e)
        return False


class LinxApp(Adw.Application):

    def __init__(self):
        super().__init__(application_id=APP_ID)
        self.win = None

    def do_startup(self):
        Adw.Application.do_startup(self)
        for name, handler, accels in (
            ('preferences', self._on_preferences, ['<Control>comma']),
            ('shortcuts', self._on_shortcuts, ['<Control>question']),
            ('about', self._on_about, ['F1']),
            ('quit', self._on_quit, ['<Control>q']),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect('activate', handler)
            self.add_action(action)
            self.set_accels_for_action(f'app.{name}', accels)

    def do_activate(self):
        if not self.win:
            self.win = LinxWindow(self)
            self.win.apply_color_scheme(self.win._config.get('gui', {}).get('theme', 'system'))
        self.win.present()

    def _on_quit(self, *_):
        if self.win:
            self.win.close()
        self.quit()

    def _on_about(self, *_):
        license_type = getattr(Gtk.License, 'UNLICENSE', Gtk.License.CUSTOM)
        about = Adw.AboutDialog(
            application_name='Linx',
            application_icon=APP_ID,
            developer_name='Mitchell',
            version=__version__,
            comments='Control panel for the Lian Li 8.8" Universal LCD Screen.\n'
                     'Reverse-engineered USB protocol with image, video, color, '
                     'matrix, and LED ring / ambilight control.',
            website='https://github.com/Skinflap/linx',
            issue_url='https://github.com/Skinflap/linx/issues',
            license_type=license_type,
        )
        about.present(self.win)

    def _on_shortcuts(self, *_):
        builder = Gtk.Builder.new_from_string(_SHORTCUTS_UI, -1)
        win = builder.get_object('shortcuts')
        win.set_transient_for(self.win)
        win.present()

    def _on_preferences(self, *_):
        from .widgets.preferences import build_preferences_dialog
        if self.win:
            build_preferences_dialog(self.win).present(self.win)


_SHORTCUTS_UI = """
<interface>
  <object class="GtkShortcutsWindow" id="shortcuts">
    <property name="modal">true</property>
    <child>
      <object class="GtkShortcutsSection">
        <child>
          <object class="GtkShortcutsGroup">
            <property name="title">General</property>
            <child>
              <object class="GtkShortcutsShortcut">
                <property name="accelerator">&lt;Control&gt;comma</property>
                <property name="title">Preferences</property>
              </object>
            </child>
            <child>
              <object class="GtkShortcutsShortcut">
                <property name="accelerator">&lt;Control&gt;question</property>
                <property name="title">Keyboard Shortcuts</property>
              </object>
            </child>
            <child>
              <object class="GtkShortcutsShortcut">
                <property name="accelerator">F1</property>
                <property name="title">About Linx</property>
              </object>
            </child>
            <child>
              <object class="GtkShortcutsShortcut">
                <property name="accelerator">&lt;Control&gt;q</property>
                <property name="title">Quit</property>
              </object>
            </child>
          </object>
        </child>
      </object>
    </child>
  </object>
</interface>
"""


def main():
    app = LinxApp()
    app.run(sys.argv)


if __name__ == '__main__':
    main()
