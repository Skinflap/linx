"""Systemd user service control for linx.service."""

import subprocess
import threading

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib


def _systemctl(*args):
    """Run systemctl --user and return (returncode, stdout)."""
    result = subprocess.run(
        ['systemctl', '--user', *args],
        capture_output=True, text=True, timeout=10,
    )
    return result.returncode, result.stdout.strip()


class ServiceGroup(Adw.PreferencesGroup):
    """Systemd user service status and controls."""

    def __init__(self, window):
        super().__init__(title='Service')
        self.window = window

        # -- Status row --
        self.status_row = Adw.ActionRow(title='linx.service', subtitle='checking...')
        self.status_icon = Gtk.Image.new_from_icon_name('emblem-synchronizing-symbolic')
        self.status_row.add_prefix(self.status_icon)

        refresh_btn = Gtk.Button.new_from_icon_name('view-refresh-symbolic')
        refresh_btn.set_valign(Gtk.Align.CENTER)
        refresh_btn.set_tooltip_text('Refresh status')
        refresh_btn.connect('clicked', lambda _: self.refresh())
        self.status_row.add_suffix(refresh_btn)
        self.add(self.status_row)

        # -- Control row --
        self.control_row = Adw.ActionRow(title='')

        self.start_btn = Gtk.Button(label='Start', valign=Gtk.Align.CENTER)
        self.start_btn.connect('clicked', lambda _: self._run_action('start'))
        self.control_row.add_suffix(self.start_btn)

        self.stop_btn = Gtk.Button(label='Stop', valign=Gtk.Align.CENTER)
        self.stop_btn.connect('clicked', lambda _: self._run_action('stop'))
        self.control_row.add_suffix(self.stop_btn)

        self.restart_btn = Gtk.Button(label='Restart', valign=Gtk.Align.CENTER)
        self.restart_btn.connect('clicked', lambda _: self._run_action('restart'))
        self.control_row.add_suffix(self.restart_btn)
        self.add(self.control_row)

        # -- Enable on login --
        self.enable_row = Adw.SwitchRow(title='Start on login')
        self.enable_row.connect('notify::active', self._on_enable_toggled)
        self._enable_updating = False
        self.add(self.enable_row)

        # Initial refresh
        self.refresh()

    def refresh(self):
        def _work():
            rc, status = _systemctl('is-active', 'linx.service')
            active = status == 'active'
            _, enabled = _systemctl('is-enabled', 'linx.service')
            is_enabled = enabled == 'enabled'
            GLib.idle_add(self._update_ui, active, status, is_enabled)

        threading.Thread(target=_work, daemon=True).start()

    def _update_ui(self, active, status_text, is_enabled):
        self.status_row.set_subtitle(status_text)
        # Can't start service while GUI has the device open
        gui_has_device = (self.window.lcd is not None and
                          self.window.lcd.dev is not None)
        if active:
            self.status_icon.set_from_icon_name('media-playback-start-symbolic')
            self.start_btn.set_sensitive(False)
            self.stop_btn.set_sensitive(True)
            self.restart_btn.set_sensitive(not gui_has_device)
        else:
            self.status_icon.set_from_icon_name('media-playback-stop-symbolic')
            self.start_btn.set_sensitive(not gui_has_device)
            self.stop_btn.set_sensitive(False)
            self.restart_btn.set_sensitive(False)
        if gui_has_device and not active:
            self.status_row.set_subtitle(f'{status_text} (device in use by GUI)')

        self._enable_updating = True
        self.enable_row.set_active(is_enabled)
        self._enable_updating = False

    def _run_action(self, action):
        self.start_btn.set_sensitive(False)
        self.stop_btn.set_sensitive(False)
        self.restart_btn.set_sensitive(False)

        def _work():
            rc, out = _systemctl(action, 'linx.service')
            GLib.idle_add(self._action_done, action, rc)

        threading.Thread(target=_work, daemon=True).start()

    def _action_done(self, action, rc):
        if rc != 0:
            self.window.show_toast(f'Service {action} failed')
        self.refresh()

    def _on_enable_toggled(self, row, _pspec):
        if self._enable_updating:
            return
        action = 'enable' if row.get_active() else 'disable'

        def _work():
            rc, _ = _systemctl(action, 'linx.service')
            if rc != 0:
                GLib.idle_add(self.window.show_toast, f'Service {action} failed')
                GLib.idle_add(self.refresh)

        threading.Thread(target=_work, daemon=True).start()
