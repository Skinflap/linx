import subprocess
import threading
import time

from . import constants as C
from .errors import DeviceDisconnected
from .log import get_logger

log = get_logger(__name__)


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
    event-driven -- sleeps until a new frame arrives instead of polling
    """

    def __init__(self, led_device, brightness=1.0):
        super().__init__(daemon=True)
        self.led = led_device
        self.brightness = brightness
        self.running = True
        self._frame = None
        self._lock = threading.Lock()
        self._event = threading.Event()
        self._error_count = 0

    def update_frame(self, img):
        with self._lock:
            self._frame = img
        self._event.set()

    def run(self):
        last_frame = None
        while self.running:
            self._event.wait(timeout=C.AMBI_FRAME_WAIT_S)
            self._event.clear()
            with self._lock:
                frame = self._frame
            if frame is None or frame is last_frame:
                continue
            last_frame = frame
            try:
                colors = sample_edge_colors(frame)
                bri = self.brightness
                if bri < 1.0:
                    colors = [(int(r * bri), int(g * bri), int(b * bri))
                              for r, g, b in colors]
                self.led.set_leds(colors)
                self._error_count = 0
            except DeviceDisconnected:
                log.warning("ambilight: led ring disconnected, stopping sync")
                self.running = False
            except Exception as e:
                self._error_count += 1
                if self._error_count <= 3:
                    log.warning("ambilight led error: %s", e)

    def stop(self):
        self.running = False
        self._event.set()


def _terminate(proc):
    """terminate a subprocess, escalating to kill -- never raises"""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=C.FFMPEG_KILL_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
    except OSError as e:
        log.debug("decoder terminate failed: %s", e)


def play_h264_with_ambilight(lcd, led, filepath, loop=True, ambi=None, brightness=1.0):
    """stream h264 to lcd while decoding frames in parallel for led ambilight"""
    from PIL import Image

    from .protocol import HEIGHT, WIDTH

    own_ambi = ambi is None
    if own_ambi:
        ambi = AmbilightThread(led, brightness=brightness)
        ambi.start()

    sample_w = WIDTH // C.AMBI_SAMPLE_DIVISOR
    sample_h = HEIGHT // C.AMBI_SAMPLE_DIVISOR
    frame_size = sample_w * sample_h * 3

    def _start_decoder():
        # <[|single thread -- 120x480 doesn't need more, prevents cpu explosion|]>
        # stderr -> DEVNULL: we only read stdout; a full stderr pipe would stall it.
        cmd = ['ffmpeg', '-nostdin', '-threads', '1']
        if loop:
            cmd += ['-stream_loop', '-1']
        cmd += ['-f', 'h264', '-i', filepath,
                '-f', 'rawvideo', '-pix_fmt', 'rgb24',
                '-s', f'{sample_w}x{sample_h}', '-r', str(C.AMBI_SAMPLE_FPS),
                '-v', 'error', '-']
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    state = {'decoder': _start_decoder()}

    def decode_loop():
        while ambi.running:
            dec = state['decoder']
            data = dec.stdout.read(frame_size)
            if not data or len(data) < frame_size:
                if not loop or not ambi.running:
                    break
                # stream_loop handles looping -- this is a fallback if it fails
                _terminate(dec)
                time.sleep(C.AMBI_DECODER_RESTART_S)
                if not ambi.running:
                    break
                state['decoder'] = _start_decoder()
                continue
            try:
                img = Image.frombytes('RGB', (sample_w, sample_h), data)
                ambi.update_frame(img)
            except Exception as e:
                log.debug("ambilight frame decode error: %s", e)

    decode_thread = threading.Thread(target=decode_loop, daemon=True)
    decode_thread.start()

    try:
        lcd.play_h264(filepath, loop=loop)
    finally:
        ambi.stop()
        _terminate(state['decoder'])
        decode_thread.join(timeout=C.FFMPEG_KILL_TIMEOUT_S)
        if own_ambi and not getattr(lcd, '_keep_display', False):
            led.off()
