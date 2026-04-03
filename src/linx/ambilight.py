# ambilight -- sample screen edges and drive led ring to match

import subprocess
import threading
import time


def sample_edge_colors(img, num_leds=60):
    """sample colors from the perimeter of a PIL Image for led edge-matching

    maps num_leds positions evenly around the perimeter and samples
    the exact pixel at each position (no block averaging -- pixel exact)

    the screen is 480w x 1920h portrait. perimeter = 2*(480+1920) = 4800px
    walk: bottom (L->R), right (B->T), top (R->L), left (T->B)
    """
    w, h = img.size
    perimeter = 2 * (w + h)
    step = perimeter / num_leds
    colors = []

    for i in range(num_leds):
        pos = i * step
        if pos < w:
            cx, cy = int(pos), h - 1
        elif pos < w + h:
            cx, cy = w - 1, h - 1 - int(pos - w)
        elif pos < 2 * w + h:
            cx, cy = w - 1 - int(pos - w - h), 0
        else:
            cx, cy = 0, int(pos - 2 * w - h)

        cx = max(0, min(cx, w - 1))
        cy = max(0, min(cy, h - 1))
        p = img.getpixel((cx, cy))
        colors.append((p[0], p[1], p[2]))

    return colors


class AmbilightThread(threading.Thread):
    """background thread that samples frames and drives the led ring

    brightness: 0.0-1.0 scalar applied to all led output
    """

    def __init__(self, led_device, brightness=1.0):
        super().__init__(daemon=True)
        self.led = led_device
        self.frame = None
        self._lock = threading.Lock()
        self.running = True
        self._error_count = 0
        self.brightness = brightness

    def update_frame(self, img):
        with self._lock:
            self.frame = img

    def run(self):
        last_frame = None
        while self.running:
            with self._lock:
                frame = self.frame
            if frame is not None and frame is not last_frame:
                last_frame = frame
                try:
                    colors = sample_edge_colors(frame)
                    bri = self.brightness
                    if bri < 1.0:
                        colors = [(int(r * bri), int(g * bri), int(b * bri))
                                  for r, g, b in colors]
                    self.led.set_leds(colors)
                    self._error_count = 0
                except Exception as e:
                    self._error_count += 1
                    if self._error_count <= 3:
                        print(f"[ambilight] LED error: {e}", flush=True)
            time.sleep(0.1)

    def stop(self):
        self.running = False


def play_h264_with_ambilight(lcd, led, filepath, loop=True, ambi=None, brightness=1.0):
    """stream h264 to lcd while decoding frames in parallel for led ambilight"""
    from PIL import Image
    from .protocol import WIDTH, HEIGHT

    own_ambi = ambi is None
    if own_ambi:
        ambi = AmbilightThread(led, brightness=brightness)
        ambi.start()

    sample_w, sample_h = WIDTH // 4, HEIGHT // 4
    frame_size = sample_w * sample_h * 3

    def _start_decoder():
        return subprocess.Popen([
            'ffmpeg', '-f', 'h264', '-i', filepath,
            '-f', 'rawvideo', '-pix_fmt', 'rgb24',
            '-s', f'{sample_w}x{sample_h}', '-r', '10',
            '-v', 'error', '-'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    state = {'decoder': _start_decoder()}

    def decode_loop():
        while ambi.running:
            dec = state['decoder']
            data = dec.stdout.read(frame_size)
            if not data or len(data) < frame_size:
                if loop and ambi.running:
                    try:
                        dec.terminate()
                        dec.wait(timeout=2)
                    except Exception:
                        pass
                    state['decoder'] = _start_decoder()
                    continue
                break
            try:
                img = Image.frombytes('RGB', (sample_w, sample_h), data)
                ambi.update_frame(img)
            except Exception:
                pass

    decode_thread = threading.Thread(target=decode_loop, daemon=True)
    decode_thread.start()

    try:
        lcd.play_h264(filepath, loop=loop)
    finally:
        ambi.stop()
        try:
            state['decoder'].terminate()
            state['decoder'].wait(timeout=2)
        except (subprocess.TimeoutExpired, Exception):
            try:
                state['decoder'].kill()
            except Exception:
                pass
        if own_ambi:
            led.off()
