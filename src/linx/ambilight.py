"""Ambilight -- sample screen edges and drive LED ring to match."""

import subprocess
import threading
import time


def sample_edge_colors(img, num_leds=60):
    """Sample colors from the perimeter of a PIL Image for LED edge-matching.

    Maps `num_leds` positions evenly around the image perimeter and returns
    the average color in a small region at each position.

    The screen is 480 wide x 1920 tall (portrait). Perimeter = 2*(480+1920) = 4800px.
    We walk: bottom edge (L->R), right edge (B->T), top edge (R->L), left edge (T->B).
    """
    w, h = img.size
    perimeter = 2 * (w + h)
    step = perimeter / num_leds
    sample_size = 8  # average an 8x8 block at each point
    colors = []

    for i in range(num_leds):
        pos = i * step
        # Bottom edge: left to right (y = h-1)
        if pos < w:
            cx, cy = int(pos), h - 1
        # Right edge: bottom to top (x = w-1)
        elif pos < w + h:
            cx, cy = w - 1, h - 1 - int(pos - w)
        # Top edge: right to left (y = 0)
        elif pos < 2 * w + h:
            cx, cy = w - 1 - int(pos - w - h), 0
        # Left edge: top to bottom (x = 0)
        else:
            cx, cy = 0, int(pos - 2 * w - h)

        # Sample a small block around the point
        x0 = max(0, cx - sample_size // 2)
        y0 = max(0, cy - sample_size // 2)
        x1 = min(w, x0 + sample_size)
        y1 = min(h, y0 + sample_size)
        region = img.crop((x0, y0, x1, y1))
        pixels = list(region.getdata())
        if pixels:
            r = sum(p[0] for p in pixels) // len(pixels)
            g = sum(p[1] for p in pixels) // len(pixels)
            b = sum(p[2] for p in pixels) // len(pixels)
            colors.append((r, g, b))
        else:
            colors.append((0, 0, 0))

    return colors


class AmbilightThread(threading.Thread):
    """Background thread that updates LEDs from a shared frame reference.

    The main loop sets `self.frame` to a PIL Image whenever it has a new one.
    This thread picks it up, samples edges, and sends to the LED device.
    Runs at ~10 LED updates/second to avoid overwhelming the HID bus.
    """

    def __init__(self, led_device, grayscale_max=0):
        super().__init__(daemon=True)
        self.led = led_device
        self.frame = None
        self._lock = threading.Lock()
        self.running = True
        self._error_count = 0
        self.grayscale_max = grayscale_max  # 0 = full color, >0 = grayscale capped at this value

    def update_frame(self, img):
        """Called by the producer (main thread) with a new PIL Image."""
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
                    if self.grayscale_max > 0:
                        # Convert to grayscale intensity, scaled to max brightness
                        gmax = self.grayscale_max
                        colors = [
                            (min(gmax, int((r * 0.299 + g * 0.587 + b * 0.114) / 255.0 * gmax)),) * 3
                            for r, g, b in colors
                        ]
                    self.led.set_leds(colors)
                    self._error_count = 0
                except Exception as e:
                    self._error_count += 1
                    if self._error_count <= 3:
                        print(f"[ambilight] LED error: {e}", flush=True)
            time.sleep(0.1)  # ~10 updates/sec

    def stop(self):
        self.running = False


def play_h264_with_ambilight(lcd, led, filepath, loop=True, ambi=None, grayscale_max=0):
    """Stream H.264 to LCD while decoding frames in parallel for LED ambilight.

    Runs ffmpeg to decode the video into raw frames in a background thread,
    feeds those frames to the ambilight sampler, while the main thread
    streams the original H.264 to the device.

    If `ambi` is provided, reuses that AmbilightThread instead of creating a new one.
    """
    from PIL import Image
    from .protocol import WIDTH, HEIGHT

    own_ambi = ambi is None
    if own_ambi:
        ambi = AmbilightThread(led, grayscale_max=grayscale_max)
        ambi.start()

    # Decode at reduced resolution for LED sampling -- much faster
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
                # EOF -- if looping, restart decoder
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
            except Exception as e:
                print(f"[ambilight] decode error: {e}", flush=True)

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
