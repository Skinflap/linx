# preferences dialog -- appearance, device, ambilight, service defaults
#
# every row persists immediately to the window's config (the same dict the
# window saves on close), so changes survive restart.

import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Adw, Gtk

from ..config import save_config

_THEMES = ['system', 'light', 'dark']
_SERVICE_MODES = ['matrix', 'color', 'image', 'play']


def build_preferences_dialog(window):
    cfg = window._config
    dialog = Adw.PreferencesDialog()
    page = Adw.PreferencesPage(title='Preferences', icon_name='preferences-system-symbolic')
    dialog.add(page)

    def persist(section, key, value):
        cfg.setdefault(section, {})[key] = value
        save_config(cfg)

    # ---==<appearance>==---
    appearance = Adw.PreferencesGroup(title='Appearance')
    page.add(appearance)

    theme_row = Adw.ComboRow(title='Theme', model=Gtk.StringList.new(['System', 'Light', 'Dark']))
    cur_theme = cfg.get('gui', {}).get('theme', 'system')
    theme_row.set_selected(_THEMES.index(cur_theme) if cur_theme in _THEMES else 0)

    def on_theme(row, _pspec):
        name = _THEMES[row.get_selected()]
        window.apply_color_scheme(name)
        persist('gui', 'theme', name)
    theme_row.connect('notify::selected', on_theme)
    appearance.add(theme_row)

    # ---==<device>==---
    device = Adw.PreferencesGroup(title='Device')
    page.add(device)

    rot_row = Adw.ComboRow(title='Rotation', subtitle='Physical panel orientation',
                           model=Gtk.StringList.new(['0°', '90°', '180°', '270°']))
    cur_rot = cfg.get('display', {}).get('rotation', 0)
    rot_row.set_selected(cur_rot if 0 <= cur_rot <= 3 else 0)

    def on_rot(row, _pspec):
        idx = row.get_selected()
        persist('display', 'rotation', idx)
        lcd = window.lcd
        if lcd and lcd.dev:
            window.run_device_op(lambda: lcd.set_rotation(idx), error_prefix='Rotation: ')
    rot_row.connect('notify::selected', on_rot)
    device.add(rot_row)

    # ---==<ambilight>==---
    ambi = Adw.PreferencesGroup(title='Ambilight')
    page.add(ambi)

    ambi_row = Adw.SwitchRow(title='Enable by default',
                             subtitle='Sync the LED ring to screen edges during playback')
    ambi_row.set_active(bool(cfg.get('ambilight', {}).get('enabled', False)))
    ambi_row.connect('notify::active',
                     lambda r, _p: persist('ambilight', 'enabled', r.get_active()))
    ambi.add(ambi_row)

    # ---==<service>==---
    svc = Adw.PreferencesGroup(title='Service',
                               description='Defaults for the systemd background service')
    page.add(svc)

    mode_row = Adw.ComboRow(title='Default mode',
                            model=Gtk.StringList.new(['Matrix', 'Color', 'Image', 'Play']))
    cur_mode = cfg.get('service', {}).get('mode', 'matrix')
    mode_row.set_selected(_SERVICE_MODES.index(cur_mode) if cur_mode in _SERVICE_MODES else 0)
    mode_row.connect('notify::selected',
                     lambda r, _p: persist('service', 'mode', _SERVICE_MODES[r.get_selected()]))
    svc.add(mode_row)

    return dialog
