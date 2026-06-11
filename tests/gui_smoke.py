"""headless GTK construction smoke test -- NOT a pytest test (needs a display).

run under a virtual display:  xvfb-run -a python tests/gui_smoke.py
builds the full window/widget tree and exits 0 if nothing raises. catches
construction/import/signal-wiring errors without a real session or hardware.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

import gi  # noqa: E402

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import GLib  # noqa: E402

from linx.gui import LinxApp  # noqa: E402


def main():
    app = LinxApp()
    app.register(None)

    holder = {}

    def on_activate(a):
        # build the window, then exercise the menu actions so the About /
        # Preferences / Shortcuts dialogs are constructed too
        for action in ('preferences', 'about', 'shortcuts'):
            try:
                a.activate_action(action, None)
            except Exception as e:  # noqa: BLE001
                print(f'action {action} raised: {e}', file=sys.stderr)
                holder['fail'] = True
        _check_controller(a.win, holder)
        holder['ok'] = True

    app.connect_after('activate', on_activate)  # after do_activate builds the window
    app.activate()
    # drain any pending idle work (deferred state restore, etc.)
    ctx = GLib.MainContext.default()
    for _ in range(200):
        if not ctx.pending():
            break
        ctx.iteration(False)
    if not holder.get('ok'):
        print('activate never fired', file=sys.stderr)
        return 1
    if holder.get('fail'):
        return 1
    print('GUI constructed OK')
    return 0


def _check_controller(win, holder):
    """verify the new controller wiring without touching hardware"""
    from types import SimpleNamespace

    import usb.core

    # window.lcd/led delegate to the controller
    sentinel = object()
    win.controller.lcd = sentinel
    if win.lcd is not sentinel:
        print('FAIL: lcd property does not delegate to controller', file=sys.stderr)
        holder['fail'] = True
    win.controller.lcd = None

    # hotplug: a vanished device while "connected" must release + update UI
    win.controller.lcd = SimpleNamespace(dev=object())
    orig_find = usb.core.find
    usb.core.find = lambda **k: None  # pretend the screen was unplugged
    try:
        win.controller._poll()
    finally:
        usb.core.find = orig_find
    if win.controller.lcd is not None:
        print('FAIL: hotplug did not release the device on unplug', file=sys.stderr)
        holder['fail'] = True


if __name__ == '__main__':
    sys.exit(main())
