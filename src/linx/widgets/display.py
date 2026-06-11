# display controls -- brightness, content mode, viewport, play/stop

import io
import os
import subprocess
import threading

import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Adw, Gio, GLib, Gtk

from ..ambilight import AmbilightThread, play_h264_with_ambilight, sample_edge_colors
from ..content import (
    encode_h264,
    generate_matrix_h264,
    make_solid_jpeg,
)
from ..protocol import CMD_PUSH_JPG, HEIGHT, WIDTH
from .viewport import ViewportEditor

MODES = ['Image', 'Video', 'Color', 'Matrix', 'Nixie Clock']
NIXIE_MODE = 4
NIXIE_SERVICE = 'nixie-clock.service'


def _nixie_systemctl(action):
    # run systemctl --user <action> nixie-clock.service, swallow errors
    try:
        return subprocess.run(
            ['systemctl', '--user', action, NIXIE_SERVICE],
            capture_output=True, text=True, timeout=10,
        ).returncode
    except Exception:
        return -1

# color-mode presets: Title-cased labels over the shared protocol table
# (+ black, which the led table calls 'off')
from ..protocol import LED_COLORS  # noqa: E402

_COLOR_KEYS = ['red', 'green', 'blue', 'white', 'black', 'cyan', 'magenta', 'yellow']
COLORS = {
    k.capitalize(): (0, 0, 0) if k == 'black' else LED_COLORS[k]
    for k in _COLOR_KEYS
}


class DisplayGroup(Adw.PreferencesGroup):
    """brightness, content mode, viewport editor, play/stop"""

    def __init__(self, window, config=None):
        super().__init__(title='Display')
        self.window = window
        self._playing = False
        self._play_thread = None
        self._temp_file = None
        self._crop = None
        self._rotation = 0
        self._config = config or {}

        # ---==<brightness>==---
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

        # ---==<mode selector>==---
        self.mode_model = Gtk.StringList.new(MODES)
        self.mode_row = Adw.ComboRow(title='Mode', model=self.mode_model)
        self.mode_row.connect('notify::selected', self._on_mode_changed)
        self.add(self.mode_row)

        # ---==<viewport>==---
        self.viewport_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.viewport = ViewportEditor()
        self.viewport.set_on_crop_changed(self._on_crop_changed)
        self.viewport.set_live_push_fn(self._live_push_to_device)
        self.viewport_box.append(self.viewport)
        self.add(self.viewport_box)

        # ---==<mode controls>==---
        # image
        self.image_row = Adw.ActionRow(title='File')
        self.image_path = None
        self.image_btn = Gtk.Button(label='Choose...', valign=Gtk.Align.CENTER)
        self.image_btn.connect('clicked', self._on_pick_image)
        self.image_row.add_suffix(self.image_btn)

        # video
        self.video_row = Adw.ActionRow(title='File')
        self.video_path = None
        self.video_btn = Gtk.Button(label='Choose...', valign=Gtk.Align.CENTER)
        self.video_btn.connect('clicked', self._on_pick_video)
        self.video_row.add_suffix(self.video_btn)

        self.loop_row = Adw.SwitchRow(title='Loop', active=True)

        # color
        self.color_model = Gtk.StringList.new(list(COLORS.keys()))
        self.color_row = Adw.ComboRow(title='Color', model=self.color_model)

        # matrix
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

        # ---==<play/stop>==---
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
        # viewport visible for image and video modes
        self.viewport_box.set_visible(idx in (0, 1))

    def _on_mode_changed(self, combo, _pspec):
        self._show_mode(combo.get_selected())

    def _on_brightness(self, scale):
        lcd = self.window.lcd
        if lcd and lcd.dev:
            val = int(scale.get_value())
            threading.Thread(target=lcd.set_brightness, args=(val,), daemon=True).start()

    def _on_crop_changed(self, x, y, w, h, rotation):
        self._crop = (x, y, w, h)
        self._rotation = rotation

    def _live_push_to_device(self, pil_image):
        """push cropped image to device -- called from viewport live sync"""
        lcd = self.window.lcd
        if not lcd or not lcd.dev:
            return
        # always stop + clear before pushing to avoid layer bleed
        lcd.stop_play()
        buf = io.BytesIO()
        pil_image.save(buf, format='JPEG', quality=85)
        lcd.push_image(buf.getvalue(), CMD_PUSH_JPG)

    # ---==<file pickers>==---

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
            # load into viewport
            self._load_image_preview(self.image_path)
        except GLib.Error:
            pass

    def _load_image_preview(self, path, on_loaded=None):
        """load image into viewport -- thumbnail for display, full-res for device.

        on_loaded (if given) runs on the UI thread once the source is set --
        used to restore rotation deterministically instead of a fixed delay.
        """
        def _work():
            from PIL import Image
            try:
                full = Image.open(path).convert('RGB')
                # thumbnail for the viewport canvas
                preview = full.copy()
                max_dim = 1200
                if preview.width > max_dim or preview.height > max_dim:
                    preview.thumbnail((max_dim, max_dim), Image.LANCZOS)
            except Exception as e:
                GLib.idle_add(self.window.show_toast, f'Could not load image: {e}')
                return

            def _apply():
                self.viewport.set_source(preview, full)
                if on_loaded:
                    on_loaded()
                return False
            GLib.idle_add(_apply)
        threading.Thread(target=_work, daemon=True).start()

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
            # extract first frame for viewport
            self._load_video_preview(self.video_path)
        except GLib.Error:
            pass

    def _load_video_preview(self, path):
        """extract first frame from video for viewport preview"""
        def _work():
            import subprocess

            from PIL import Image
            try:
                # extract one frame at low res -- fast
                r = subprocess.run([
                    'ffmpeg', '-i', path, '-frames:v', '1',
                    '-f', 'image2pipe', '-vcodec', 'png', '-'
                ], capture_output=True, timeout=10)
                if r.returncode == 0 and r.stdout:
                    import io
                    img = Image.open(io.BytesIO(r.stdout)).convert('RGB')
                    max_dim = 1200
                    if img.width > max_dim or img.height > max_dim:
                        img.thumbnail((max_dim, max_dim), Image.LANCZOS)
                    GLib.idle_add(self.viewport.set_source, img)
            except Exception:
                pass
        threading.Thread(target=_work, daemon=True).start()

    # ---==<play / stop>==---

    def _set_playing(self, playing):
        self._playing = playing
        self.play_btn.set_sensitive(not playing)
        self.stop_btn.set_sensitive(playing)
        if playing:
            self.spinner.start()
        else:
            self.spinner.stop()

    def _get_ambilight_state(self):
        led = self.window.led
        use_ambi = (led and led.dev and
                    self.window.led_group.ambilight_row.get_active())
        bri = self.window.led_group.get_brightness() if use_ambi else 1.0
        return led, use_ambi, bri

    def _on_play(self, btn):
        mode = self.mode_row.get_selected()

        # ---==<nixie mode>==---
        # nixie hands off to its own systemd service -- gui drops the device
        if mode == NIXIE_MODE:
            self._set_playing(True)
            threading.Thread(target=self._do_nixie_handoff, daemon=True).start()
            return

        lcd = self.window.lcd
        if not lcd or not lcd.dev:
            self.window.show_toast('Not connected')
            return

        led, use_ambi, bri = self._get_ambilight_state()

        args = {'led': led, 'use_ambi': use_ambi, 'bri': bri,
                'crop': self._crop}
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
            args['color_rgb'] = COLORS[color_name]
        elif mode == 3:
            args['duration'] = int(self.duration_row.get_value())
            args['fps'] = int(self.fps_row.get_value())

        self._set_playing(True)
        old_thread = self._play_thread

        def _worker():
            try:
                if old_thread and old_thread.is_alive():
                    lcd.request_stop()
                    old_thread.join(timeout=10)

                # stop nixie-clock if it's running -- it would fight for usb
                _nixie_systemctl('stop')

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

    # ---==<mode implementations>==---

    def _do_image(self, lcd, args):
        # use viewport's cropped+rotated image if available
        img = self.viewport.get_cropped_image()
        if img is None:
            from PIL import Image
            img = Image.open(args['path']).convert('RGB')
            img = img.resize((WIDTH, HEIGHT), Image.LANCZOS)

        if args['use_ambi']:
            colors = sample_edge_colors(img)
            bri = args['bri']
            if bri < 1.0:
                colors = [(int(r*bri), int(g*bri), int(b*bri)) for r, g, b in colors]
            args['led'].set_leds(colors)

        # push as jpeg to background layer -- png overlay doesn't display reliably
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=95)
        lcd.push_image(buf.getvalue(), CMD_PUSH_JPG)
        GLib.idle_add(self._set_playing, False)

    def _do_video(self, lcd, args):
        filepath = args['path']
        need_cleanup = False
        if not filepath.endswith('.h264'):
            GLib.idle_add(self.window.show_toast, 'Encoding video…')
            rot = getattr(self, '_rotation', 0)
            crop = self._scale_crop_for_video(filepath, rot)
            filepath = encode_h264(filepath, crop=crop, rotation=rot)
            if not filepath:
                GLib.idle_add(self.window.show_toast, 'Encoding failed')
                GLib.idle_add(self._set_playing, False)
                return
            need_cleanup = True

        self._temp_file = filepath if need_cleanup else None

        if args['use_ambi']:
            play_h264_with_ambilight(lcd, args['led'], filepath,
                                     loop=args['loop'], brightness=args['bri'])
        else:
            lcd.play_h264(filepath, loop=args['loop'])

        GLib.idle_add(self._set_playing, False)

    def _do_color(self, lcd, args):
        rgb = args['color_rgb']
        if args['use_ambi']:
            bri = args['bri']
            args['led'].set_all(int(rgb[0]*bri), int(rgb[1]*bri), int(rgb[2]*bri))

        jpg = make_solid_jpeg(color=rgb)
        lcd.push_image(jpg, CMD_PUSH_JPG)
        GLib.idle_add(self._set_playing, False)

    def _do_nixie_handoff(self):
        # release the gui's hold on the device so nixie-clock.service can grab it
        lcd = self.window.lcd
        if lcd:
            try:
                if lcd._stop is False and lcd.dev:
                    lcd.request_stop()
            except Exception:
                pass
            play_thread = self._play_thread
            if play_thread and play_thread.is_alive():
                play_thread.join(timeout=5)
            try:
                lcd.stop_play()
            except Exception:
                pass
            try:
                lcd.close()
            except Exception:
                pass
        led = self.window.led
        if led:
            try:
                led.close()
            except Exception:
                pass

        self.window.lcd = None
        self.window.led = None

        rc = _nixie_systemctl('start')

        def _finish():
            self.window.status_group.mark_disconnected()
            self.window.on_connection_changed()
            self._set_playing(False)
            if rc == 0:
                self.window.show_toast('Nixie Clock running')
            else:
                self.window.show_toast('Failed to start nixie-clock.service')
            return False

        GLib.idle_add(_finish)

    def _do_matrix(self, lcd, args):
        ambi = None
        if args['use_ambi']:
            ambi = AmbilightThread(args['led'], brightness=args['bri'])
            ambi.start()

        h264 = generate_matrix_h264(duration=args['duration'], fps=args['fps'],
                                     ambilight=ambi)
        self._temp_file = h264

        if args['use_ambi']:
            play_h264_with_ambilight(lcd, args['led'], h264, loop=True, ambi=ambi,
                                     brightness=args['bri'])
        else:
            lcd.play_h264(h264, loop=True)

        if ambi:
            ambi.stop()
        GLib.idle_add(self._set_playing, False)

    def _scale_crop_for_video(self, video_path, rotation):
        """scale viewport crop coords from preview space to full video dimensions"""
        crop = self._crop
        if not crop:
            return None
        # get original video dimensions
        import subprocess
        try:
            r = subprocess.run([
                'ffprobe', '-v', 'error', '-select_streams', 'v:0',
                '-show_entries', 'stream=width,height',
                '-of', 'csv=p=0', video_path
            ], capture_output=True, timeout=5)
            w, h = [int(x) for x in r.stdout.decode().strip().split(',')]
        except Exception:
            return None

        # after rotation, video dimensions change
        if rotation in (90, 270):
            rot_w, rot_h = h, w
        else:
            rot_w, rot_h = w, h

        # viewport preview dimensions (rotated source thumbnail)
        vp_w = self.viewport._src_w
        vp_h = self.viewport._src_h
        if vp_w <= 0 or vp_h <= 0:
            return None

        # scale crop from preview to full rotated video, clamped to bounds
        sx = rot_w / vp_w
        sy = rot_h / vp_h
        cx, cy, cw, ch = crop
        cx = max(0, int(cx * sx))
        cy = max(0, int(cy * sy))
        cw = min(int(cw * sx), rot_w - cx)
        ch = min(int(ch * sy), rot_h - cy)
        if cw <= 0 or ch <= 0:
            return None
        return (cx, cy, cw, ch)

    def restore_state(self):
        """restore gui state from config -- call after widget construction"""
        gui = self._config.get('gui', {})
        display = self._config.get('display', {})

        self.brightness_scale.set_value(display.get('brightness', 80))

        mode = gui.get('mode', 0)
        self.mode_row.set_selected(mode)

        rot = gui.get('image_rotation', 0)
        saved_crop = gui.get('crop')

        def _restore_rotation():
            # runs once the viewport source is actually loaded -- no fixed delay
            if self.viewport._source_orig is None:
                return
            if rot:
                self.viewport._rotation = rot
                self.viewport._apply_rotation()
            # apply crop after rotation (rotation resets the crop to fit)
            if saved_crop:
                self.viewport.set_crop_state(saved_crop)
            self.viewport._canvas.queue_draw()

        img_path = gui.get('image_path', '')
        if img_path and os.path.exists(img_path):
            self.image_path = img_path
            self.image_row.set_subtitle(os.path.basename(img_path))
            self._load_image_preview(img_path, on_loaded=_restore_rotation)

        vid_path = gui.get('video_path', '')
        if vid_path and os.path.exists(vid_path):
            self.video_path = vid_path
            self.video_row.set_subtitle(os.path.basename(vid_path))
            self._load_video_preview(vid_path)

        self.color_row.set_selected(gui.get('color', 0))
        self.loop_row.set_active(gui.get('loop', True))

    def get_state(self):
        """capture current gui state for saving"""
        has_src = self.viewport._source_orig is not None
        return {
            'gui': {
                'mode': self.mode_row.get_selected(),
                'image_path': self.image_path or '',
                'video_path': self.video_path or '',
                'color': self.color_row.get_selected(),
                'loop': self.loop_row.get_active(),
                'image_rotation': self.viewport._rotation if has_src else 0,
                'crop': (self.viewport.get_crop_state() or []) if has_src else [],
            },
            'display': {
                'brightness': int(self.brightness_scale.get_value()),
            },
        }

    def set_sensitive_all(self, sensitive):
        self.brightness_scale.set_sensitive(sensitive)
        self.play_btn.set_sensitive(sensitive and not self._playing)
