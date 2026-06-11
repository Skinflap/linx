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
        holder['ok'] = True

    app.connect('activate', on_activate)
    app.activate()  # synchronously emits activate -> do_activate builds the window
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


if __name__ == '__main__':
    sys.exit(main())
