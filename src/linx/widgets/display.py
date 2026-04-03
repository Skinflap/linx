"""Display controls -- brightness, content mode, play/stop."""

import io
import os
import threading

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib, Gio

from ..protocol import WIDTH, HEIGHT
from ..content import encode_h264, generate_solid_h264, generate_matrix_h264
from ..ambilight import AmbilightThread, play_h264_with_ambilight, sample_edge_colors

MODES = ['Image', 'Video', 'Color', 'Matrix']

COLORS = {
    'Red': '0xFF0000', 'Green': '0x00FF00', 'Blue': '0x0000FF',
    'White': '0xFFFFFF', 'Black': '0x000000', 'Cyan': '0x00FFFF',
    'Magenta': '0xFF00FF', 'Yellow': '0xFFFF00',
}


class DisplayGroup(Adw.PreferencesGroup):
    """Brightness slider, content mode picker, mode-specific controls, play/stop."""

    def __init__(self, window):
        super().__init__(title='Display')
        self.window = window
        self._playing = False
        self._play_thread = None
        self._temp_file = None

        # -- Brightness --
        self.brightness_row = Adw.ActionRow(title='Brightness')
        self.brightness_scale = Gtk.Scale.new_with_range(
            Gtk.Orientation.HORIZONTAL, 0, 100, 1)
        self.brightness_scale.set_value(80)
        self.brightness_scale.set_hexpand(True)
        self.brightness_scale.set_valign(Gtk.Align.CENTER)
        self.brightness_scale.set_size_request(200, -1)
        self.brightness_scale.connect('value-changed', self._on_brightness)
        self.brightness_row.add_suffix(self.brightness_scale)
        self.add(self.brightness_row)

        # -- Mode selector --
        self.mode_model = Gtk.StringList.new(MODES)
        self.mode_row = Adw.ComboRow(title='Mode', model=self.mode_model)
        self.mode_row.connect('notify::selected', self._on_mode_changed)
        self.add(self.mode_row)

        # -- Mode-specific controls --
        # Image
        self.image_row = Adw.ActionRow(title='File')
        self.image_path = None
        self.image_btn = Gtk.Button(label='Choose...', valign=Gtk.Align.CENTER)
        self.image_btn.connect('clicked', self._on_pick_image)
        self.image_row.add_suffix(self.image_btn)

        # Video
        self.video_row = Adw.ActionRow(title='File')
        self.video_path = None
        self.video_btn = Gtk.Button(label='Choose...', valign=Gtk.Align.CENTER)
        self.video_btn.connect('clicked', self._on_pick_video)
        self.video_row.add_suffix(self.video_btn)

        self.loop_row = Adw.SwitchRow(title='Loop', active=True)

        # Color
        self.color_model = Gtk.StringList.new(list(COLORS.keys()))
        self.color_row = Adw.ComboRow(title='Color', model=self.color_model)

        # Matrix
        self.duration_row = Adw.SpinRow.new_with_range(10, 600, 10)
        self.duration_row.set_title('Duration (s)')
        self.duration_row.set_value(60)

        self.fps_row = Adw.SpinRow.new_with_range(10, 60, 5)
        self.fps_row.set_title('FPS')
        self.fps_row.set_value(30)

        self._mode_rows = {
            0: [self.image_row],
            1: [self.video_row, self.loop_row],
            2: [self.color_row],
            3: [self.duration_row, self.fps_row],
        }
        for rows in self._mode_rows.values():
            for row in rows:
                self.add(row)
        self._show_mode(0)

        # -- Play / Stop --
        self.action_row = Adw.ActionRow(title='')
        self.play_btn = Gtk.Button(label='Play', valign=Gtk.Align.CENTER)
        self.play_btn.add_css_class('suggested-action')
        self.play_btn.connect('clicked', self._on_play)
        self.action_row.add_suffix(self.play_btn)

        self.stop_btn = Gtk.Button(label='Stop', valign=Gtk.Align.CENTER)
        self.stop_btn.add_css_class('destructive-action')
        self.stop_btn.set_sensitive(False)
        self.stop_btn.connect('clicked', self._on_stop)
        self.action_row.add_suffix(self.stop_btn)

        self.spinner = Gtk.Spinner()
        self.spinner.set_valign(Gtk.Align.CENTER)
        self.action_row.add_suffix(self.spinner)
        self.add(self.action_row)

    def _show_mode(self, idx):
        for mode_idx, rows in self._mode_rows.items():
            for row in rows:
                row.set_visible(mode_idx == idx)

    def _on_mode_changed(self, combo, _pspec):
        self._show_mode(combo.get_selected())

    def _on_brightness(self, scale):
        lcd = self.window.lcd
        if lcd and lcd.dev:
            val = int(scale.get_value())
            threading.Thread(target=lcd.set_brightness, args=(val,), daemon=True).start()

    # -- File pickers --

    def _open_file_dialog(self, title, filters, callback):
        dialog = Gtk.FileDialog(title=title)
        if filters:
            filter_list = Gio.ListStore.new(Gtk.FileFilter)
            for f in filters:
                filter_list.append(f)
            dialog.set_filters(filter_list)
        dialog.open(self.window, None, callback)

    def _on_pick_image(self, btn):
        f = Gtk.FileFilter()
        f.set_name('Images')
        f.add_mime_type('image/*')
        self._open_file_dialog('Choose Image', [f], self._image_picked)

    def _image_picked(self, dialog, result):
        try:
            gfile = dialog.open_finish(result)
            self.image_path = gfile.get_path()
            self.image_row.set_subtitle(os.path.basename(self.image_path))
        except GLib.Error:
            pass

    def _on_pick_video(self, btn):
        f = Gtk.FileFilter()
        f.set_name('Videos')
        f.add_mime_type('video/*')
        f.add_pattern('*.gif')
        self._open_file_dialog('Choose Video', [f], self._video_picked)

    def _video_picked(self, dialog, result):
        try:
            gfile = dialog.open_finish(result)
            self.video_path = gfile.get_path()
            self.video_row.set_subtitle(os.path.basename(self.video_path))
        except GLib.Error:
            pass

    # -- Play / Stop --

    def _set_playing(self, playing):
        self._playing = playing
        self.play_btn.set_sensitive(not playing)
        self.stop_btn.set_sensitive(playing)
        if playing:
            self.spinner.start()
        else:
            self.spinner.stop()

    def _get_ambilight_state(self):
        """Read ambilight settings from GTK widgets (main thread only)."""
        led = self.window.led
        use_ambi = (led and led.dev and
                    self.window.led_group.ambilight_row.get_active())
        gs = int(self.window.led_group.grayscale_row.get_value()) if use_ambi else 0
        return led, use_ambi, gs

    def _on_play(self, btn):
        """Start playback. Captures GTK state, then dispatches to worker thread."""
        lcd = self.window.lcd
        if not lcd or not lcd.dev:
            self.window.show_toast('Not connected')
            return

        mode = self.mode_row.get_selected()
        led, use_ambi, gs = self._get_ambilight_state()

        # Capture mode-specific state from GTK widgets
        args = {'led': led, 'use_ambi': use_ambi, 'gs': gs}
        if mode == 0:
            if not self.image_path:
                self.window.show_toast('No image selected')
                return
            args['path'] = self.image_path
        elif mode == 1:
            if not self.video_path:
                self.window.show_toast('No video selected')
                return
            args['path'] = self.video_path
            args['loop'] = self.loop_row.get_active()
        elif mode == 2:
            color_name = list(COLORS.keys())[self.color_row.get_selected()]
            args['color_name'] = color_name
            args['color_val'] = COLORS[color_name]
        elif mode == 3:
            args['duration'] = int(self.duration_row.get_value())
            args['fps'] = int(self.fps_row.get_value())

        # Disable buttons, start spinner
        self._set_playing(True)

        old_thread = self._play_thread

        def _worker():
            try:
                if old_thread and old_thread.is_alive():
                    lcd.request_stop()
                    old_thread.join(timeout=10)

                lcd.stop_play()
                lcd.clear_layers()

                if self._temp_file and os.path.exists(self._temp_file):
                    os.unlink(self._temp_file)
                    self._temp_file = None

                lcd.init()
                lcd.prepare_display()

                if mode == 0:
                    self._do_image(lcd, args)
                elif mode == 1:
                    self._do_video(lcd, args)
                elif mode == 2:
                    self._do_color(lcd, args)
                elif mode == 3:
                    self._do_matrix(lcd, args)
            except Exception as e:
                GLib.idle_add(self.window.show_toast, str(e))
                GLib.idle_add(self._set_playing, False)

        self._play_thread = threading.Thread(target=_worker, daemon=True)
        self._play_thread.start()

    def _on_stop(self, btn):
        """Stop playback. Runs cleanup in background so UI doesn't freeze."""
        lcd = self.window.lcd
        if not lcd:
            return
        self.stop_btn.set_sensitive(False)
        play_thread = self._play_thread

        def _worker():
            lcd.request_stop()
            if play_thread and play_thread.is_alive():
                play_thread.join(timeout=10)
            try:
                lcd.stop_play()
                lcd.clear_layers()
            except Exception:
                pass
            if self._temp_file and os.path.exists(self._temp_file):
                os.unlink(self._temp_file)
                self._temp_file = None
            GLib.idle_add(self._set_playing, False)

        threading.Thread(target=_worker, daemon=True).start()

    # -- Mode implementations (all run on worker thread, device is exclusively ours) --

    def _do_image(self, lcd, args):
        from PIL import Image
        img = Image.open(args['path']).convert('RGB')
        img = img.resize((WIDTH, HEIGHT), Image.LANCZOS)

        if args['use_ambi']:
            colors = sample_edge_colors(img)
            args['led'].set_leds(colors)

        buf = io.BytesIO()
        img.save(buf, format='PNG')
        lcd.push_png(buf.getvalue())
        GLib.idle_add(self._set_playing, False)

    def _do_video(self, lcd, args):
        filepath = args['path']
        need_cleanup = False
        if not filepath.endswith('.h264'):
            filepath = encode_h264(filepath)
            if not filepath:
                GLib.idle_add(self.window.show_toast, 'Encoding failed')
                GLib.idle_add(self._set_playing, False)
                return
            need_cleanup = True

        self._temp_file = filepath if need_cleanup else None

        if args['use_ambi']:
            play_h264_with_ambilight(lcd, args['led'], filepath,
                                     loop=args['loop'], grayscale_max=args['gs'])
        else:
            lcd.play_h264(filepath, loop=args['loop'])

        GLib.idle_add(self._set_playing, False)

    def _do_color(self, lcd, args):
        if args['use_ambi']:
            from ..protocol import LED_COLORS
            if args['color_name'].lower() in LED_COLORS:
                args['led'].set_all(*LED_COLORS[args['color_name'].lower()])

        h264 = generate_solid_h264(args['color_val'])
        self._temp_file = h264
        lcd.play_h264(h264, loop=True)
        GLib.idle_add(self._set_playing, False)

    def _do_matrix(self, lcd, args):
        ambi = None
        if args['use_ambi']:
            ambi = AmbilightThread(args['led'], grayscale_max=args['gs'])
            ambi.start()

        h264 = generate_matrix_h264(duration=args['duration'], fps=args['fps'],
                                     ambilight=ambi)
        self._temp_file = h264

        if args['use_ambi']:
            play_h264_with_ambilight(lcd, args['led'], h264, loop=True, ambi=ambi,
                                     grayscale_max=args['gs'])
        else:
            lcd.play_h264(h264, loop=True)

        if ambi:
            ambi.stop()
        GLib.idle_add(self._set_playing, False)

    def set_sensitive_all(self, sensitive):
        """Enable/disable controls based on connection state."""
        self.brightness_scale.set_sensitive(sensitive)
        self.play_btn.set_sensitive(sensitive and not self._playing)
