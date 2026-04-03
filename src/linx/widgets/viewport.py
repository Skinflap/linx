# viewport editor -- drag a crop box over rotated source content
#
# the physical screen is 480x1920 portrait, pixel (0,0) at top-left
# rotation rotates THE IMAGE, crop box is always 480:1920 portrait
# rotate the source until your content is upright, then position the crop

import io
import threading

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, GLib
import cairo

from ..protocol import WIDTH, HEIGHT

DEVICE_RATIO = WIDTH / HEIGHT  # 0.25


class ViewportEditor(Gtk.Box):

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)

        self._canvas = Gtk.DrawingArea()
        self._canvas.set_size_request(400, 300)
        self._canvas.set_vexpand(False)
        self._canvas.set_hexpand(True)
        self._canvas.set_draw_func(self._draw)
        self.append(self._canvas)

        # controls
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        controls.set_halign(Gtk.Align.CENTER)
        controls.set_margin_top(4)
        controls.set_margin_bottom(4)

        rot_left = Gtk.Button(icon_name='object-rotate-left-symbolic')
        rot_left.set_tooltip_text('Rotate image left')
        rot_left.connect('clicked', lambda _: self._do_rotate(-90))
        controls.append(rot_left)

        rot_right = Gtk.Button(icon_name='object-rotate-right-symbolic')
        rot_right.set_tooltip_text('Rotate image right')
        rot_right.connect('clicked', lambda _: self._do_rotate(90))
        controls.append(rot_right)

        self._rot_label = Gtk.Label(label='0°')
        controls.append(self._rot_label)

        self._live_toggle = Gtk.ToggleButton(label='Live')
        self._live_toggle.set_tooltip_text('Push to device as you drag')
        controls.append(self._live_toggle)

        self.append(controls)

        # original source (unrotated)
        self._source_orig = None
        self._source_full_orig = None

        # rotated source (what we display and crop from)
        self._source_surface = None
        self._src_w = 0
        self._src_h = 0
        self._full_rotated = None

        # crop in rotated-source coordinates -- always portrait ratio
        self._crop_x = 0.0
        self._crop_y = 0.0
        self._crop_w = 0.0
        self._crop_h = 0.0

        self._rotation = 0  # applied to source image

        # interaction
        self._dragging = False
        self._resizing = False
        self._drag_sx = 0.0
        self._drag_sy = 0.0
        self._drag_cx = 0.0
        self._drag_cy = 0.0
        self._resize_edge = None

        self._on_crop_changed = None
        self._live_push_fn = None
        self._live_pending = False
        self._live_lock = threading.Lock()

        # gestures
        click = Gtk.GestureClick()
        click.connect('pressed', self._on_press)
        click.connect('released', self._on_release)
        self._canvas.add_controller(click)

        drag = Gtk.GestureDrag()
        drag.connect('drag-begin', self._on_drag_begin)
        drag.connect('drag-update', self._on_drag_update)
        drag.connect('drag-end', self._on_drag_end)
        self._canvas.add_controller(drag)

        scroll = Gtk.EventControllerScroll(
            flags=Gtk.EventControllerScrollFlags.VERTICAL)
        scroll.connect('scroll', self._on_scroll)
        self._canvas.add_controller(scroll)

    def set_on_crop_changed(self, cb):
        self._on_crop_changed = cb

    def set_live_push_fn(self, fn):
        self._live_push_fn = fn

    # ---==<source management>==---

    def set_source(self, preview, full_res=None):
        if preview is None:
            self._source_orig = None
            self._source_full_orig = None
            self._source_surface = None
            self._full_rotated = None
            self._src_w = self._src_h = 0
            self._canvas.queue_draw()
            return
        self._source_orig = preview
        self._source_full_orig = full_res or preview
        self._rotation = 0
        self._apply_rotation()
        self._canvas.queue_draw()

    def _apply_rotation(self):
        from PIL import Image
        p = self._source_orig
        f = self._source_full_orig
        if self._rotation == 90:
            p = p.transpose(Image.ROTATE_270)
            f = f.transpose(Image.ROTATE_270)
        elif self._rotation == 180:
            p = p.transpose(Image.ROTATE_180)
            f = f.transpose(Image.ROTATE_180)
        elif self._rotation == 270:
            p = p.transpose(Image.ROTATE_90)
            f = f.transpose(Image.ROTATE_90)

        self._full_rotated = f
        self._src_w = p.width
        self._src_h = p.height

        # build cairo surface
        buf = io.BytesIO()
        p.convert('RGBA').save(buf, format='PNG')
        buf.seek(0)
        self._source_surface = cairo.ImageSurface.create_from_png(buf)

        self._fit_crop()
        self._rot_label.set_label(f'{self._rotation}°')

    def _do_rotate(self, delta):
        if self._source_orig is None:
            return
        self._rotation = (self._rotation + delta) % 360
        self._apply_rotation()
        self._canvas.queue_draw()
        self._notify()
        self._live_push()

    def _fit_crop(self):
        """largest portrait crop that fits the rotated source"""
        if self._src_w <= 0 or self._src_h <= 0:
            return
        cw = self._src_w
        ch = cw / DEVICE_RATIO
        if ch > self._src_h:
            ch = self._src_h
            cw = ch * DEVICE_RATIO
        self._crop_w = cw
        self._crop_h = ch
        self._crop_x = (self._src_w - cw) / 2
        self._crop_y = (self._src_h - ch) / 2

    # ---==<output>==---

    def get_cropped_image(self):
        """crop from rotated full-res source, resize to device dimensions"""
        from PIL import Image
        src = self._full_rotated
        if src is None:
            return None
        # scale crop coords from preview to full-res
        sx = src.width / self._src_w if self._src_w > 0 else 1
        sy = src.height / self._src_h if self._src_h > 0 else 1
        x = max(0, int(self._crop_x * sx))
        y = max(0, int(self._crop_y * sy))
        w = min(int(self._crop_w * sx), src.width - x)
        h = min(int(self._crop_h * sy), src.height - y)
        if w <= 0 or h <= 0:
            return None
        return src.crop((x, y, x + w, y + h)).resize((WIDTH, HEIGHT), Image.LANCZOS)

    # ---==<coordinate mapping>==---

    def _xform(self):
        a = self._canvas.get_allocation()
        w, h = a.width, a.height
        if self._src_w <= 0 or self._src_h <= 0 or w <= 0 or h <= 0:
            return 1.0, 0.0, 0.0
        pad = 12
        s = min((w - pad*2) / self._src_w, (h - pad*2) / self._src_h)
        ox = pad + ((w - pad*2) - self._src_w * s) / 2
        oy = pad + ((h - pad*2) - self._src_h * s) / 2
        return s, ox, oy

    def _w2s(self, wx, wy):
        s, ox, oy = self._xform()
        return (wx - ox) / s if s > 0 else 0, (wy - oy) / s if s > 0 else 0

    def _s2w(self, sx, sy):
        s, ox, oy = self._xform()
        return sx * s + ox, sy * s + oy

    # ---==<drawing>==---

    def _draw(self, area, cr, width, height):
        cr.set_source_rgb(0.1, 0.1, 0.1)
        cr.paint()

        if self._source_surface is None:
            cr.set_source_rgb(0.3, 0.3, 0.3)
            cr.set_font_size(13)
            t = "select an image or video"
            ext = cr.text_extents(t)
            cr.move_to((width - ext.width) / 2, (height + ext.height) / 2)
            cr.show_text(t)
            return

        s, ox, oy = self._xform()

        # source image
        cr.save()
        cr.translate(ox, oy)
        cr.scale(s, s)
        cr.set_source_surface(self._source_surface, 0, 0)
        cr.get_source().set_filter(cairo.FILTER_BILINEAR)
        cr.paint()
        cr.restore()

        # dim outside crop
        cx, cy = self._s2w(self._crop_x, self._crop_y)
        cw, ch = self._crop_w * s, self._crop_h * s
        sw, sh = self._src_w * s, self._src_h * s
        cr.set_source_rgba(0, 0, 0, 0.55)
        cr.rectangle(ox, oy, sw, cy - oy); cr.fill()
        cr.rectangle(ox, cy + ch, sw, (oy + sh) - (cy + ch)); cr.fill()
        cr.rectangle(ox, cy, cx - ox, ch); cr.fill()
        cr.rectangle(cx + cw, cy, (ox + sw) - (cx + cw), ch); cr.fill()

        # crop border
        cr.set_source_rgb(1, 1, 1)
        cr.set_line_width(1.5)
        cr.rectangle(cx, cy, cw, ch)
        cr.stroke()

        # screen top indicator (always the top edge of the crop -- because
        # the IMAGE rotates, not the crop)
        cr.set_line_width(3)
        cr.set_source_rgb(0.2, 0.8, 1.0)
        cr.move_to(cx, cy)
        cr.line_to(cx + cw, cy)
        cr.stroke()
        # arrow
        mx = cx + cw / 2
        cr.move_to(mx - 6, cy + 6)
        cr.line_to(mx, cy - 1)
        cr.line_to(mx + 6, cy + 6)
        cr.fill()

        # corner handles
        cr.set_source_rgb(1, 1, 1)
        for hx, hy in [(cx, cy), (cx+cw, cy), (cx, cy+ch), (cx+cw, cy+ch)]:
            cr.rectangle(hx - 3, hy - 3, 6, 6)
            cr.fill()

    # ---==<interaction>==---

    def _hit(self, wx, wy):
        s, _, _ = self._xform()
        cx, cy = self._s2w(self._crop_x, self._crop_y)
        cw, ch = self._crop_w * s, self._crop_h * s
        m = 10
        if not (cx-m <= wx <= cx+cw+m and cy-m <= wy <= cy+ch+m):
            return None
        nl, nr = abs(wx-cx) < m, abs(wx-(cx+cw)) < m
        nt, nb = abs(wy-cy) < m, abs(wy-(cy+ch)) < m
        if nt and nl: return 'nw'
        if nt and nr: return 'ne'
        if nb and nl: return 'sw'
        if nb and nr: return 'se'
        if nt: return 'n'
        if nb: return 's'
        if nl: return 'w'
        if nr: return 'e'
        if cx <= wx <= cx+cw and cy <= wy <= cy+ch:
            return 'body'
        return None

    def _on_press(self, g, n, x, y):
        pass

    def _on_release(self, g, n, x, y):
        self._dragging = False
        self._resizing = False

    def _on_drag_begin(self, g, x, y):
        hit = self._hit(x, y)
        if hit is None:
            return
        if hit == 'body':
            self._dragging = True
            sx, sy = self._w2s(x, y)
            self._drag_sx = sx
            self._drag_sy = sy
            self._drag_cx = self._crop_x
            self._drag_cy = self._crop_y
        else:
            self._resizing = True
            self._resize_edge = hit

    def _on_drag_update(self, g, dx, dy):
        ok, sx, sy = g.get_start_point()
        if not ok:
            return
        mx, my = self._w2s(sx + dx, sy + dy)

        if self._dragging:
            nx = self._drag_cx + (mx - self._drag_sx)
            ny = self._drag_cy + (my - self._drag_sy)
            self._crop_x = max(0, min(nx, self._src_w - self._crop_w))
            self._crop_y = max(0, min(ny, self._src_h - self._crop_h))
            self._canvas.queue_draw()
            self._notify()
            self._live_push()
        elif self._resizing:
            self._do_resize(mx, my)
            self._canvas.queue_draw()
            self._notify()
            self._live_push()

    def _on_drag_end(self, g, dx, dy):
        self._dragging = False
        self._resizing = False
        self._live_push()

    def _on_scroll(self, c, dx, dy):
        if self._src_w <= 0:
            return False
        f = 0.95 if dy > 0 else 1.05
        nw = max(48, min(self._crop_w * f, self._src_w))
        nh = nw / DEVICE_RATIO
        if nh > self._src_h:
            nh = self._src_h
            nw = nh * DEVICE_RATIO
        ccx = self._crop_x + self._crop_w / 2
        ccy = self._crop_y + self._crop_h / 2
        self._crop_x = max(0, min(ccx - nw/2, self._src_w - nw))
        self._crop_y = max(0, min(ccy - nh/2, self._src_h - nh))
        self._crop_w = nw
        self._crop_h = nh
        self._canvas.queue_draw()
        self._notify()
        self._live_push()
        return True

    def _do_resize(self, sx, sy):
        e = self._resize_edge
        x1, y1 = self._crop_x, self._crop_y
        x2, y2 = x1 + self._crop_w, y1 + self._crop_h
        if 'e' in e: x2 = sx
        if 'w' in e: x1 = sx
        if 's' in e: y2 = sy
        if 'n' in e: y1 = sy
        x1 = max(0, x1); y1 = max(0, y1)
        x2 = min(self._src_w, x2); y2 = min(self._src_h, y2)
        w, h = x2-x1, y2-y1
        if w < 24 or h < 24:
            return
        # enforce portrait device ratio
        if 'e' in e or 'w' in e:
            h = w / DEVICE_RATIO
            if 'n' in e: y1 = y2 - h
            else: y2 = y1 + h
        else:
            w = h * DEVICE_RATIO
            if 'w' in e: x1 = x2 - w
            else: x2 = x1 + w
        if x1 < 0: x1 = 0; x2 = w
        if y1 < 0: y1 = 0; y2 = h
        if x2 > self._src_w: x2 = self._src_w; x1 = x2 - w
        if y2 > self._src_h: y2 = self._src_h; y1 = y2 - h
        w, h = x2-x1, y2-y1
        if w > 0 and h > 0:
            self._crop_x, self._crop_y = x1, y1
            self._crop_w, self._crop_h = w, h

    # ---==<live sync>==---

    def _live_push(self):
        if not self._live_toggle.get_active() or not self._live_push_fn:
            return
        if not self._full_rotated:
            return
        with self._live_lock:
            if self._live_pending:
                return
            self._live_pending = True
        def _go():
            try:
                img = self.get_cropped_image()
                if img:
                    self._live_push_fn(img)
            finally:
                with self._live_lock:
                    self._live_pending = False
        threading.Thread(target=_go, daemon=True).start()

    def _notify(self):
        if self._on_crop_changed:
            self._on_crop_changed(
                int(self._crop_x), int(self._crop_y),
                int(self._crop_w), int(self._crop_h), self._rotation)
