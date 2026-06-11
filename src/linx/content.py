import contextlib
import io
import os
import random
import subprocess
import tempfile

from . import constants as C
from .errors import EncodeError
from .log import get_logger
from .protocol import HEIGHT, LED_COLORS, WIDTH

log = get_logger(__name__)


# --<|||encoder detection|||>--

def _has_nvenc():
    """check if h264_nvenc is available -- cached"""
    if not hasattr(_has_nvenc, '_result'):
        try:
            r = subprocess.run(
                ['ffmpeg', '-hide_banner', '-encoders'],
                capture_output=True, timeout=C.FFMPEG_PROBE_TIMEOUT_S)
            _has_nvenc._result = b'h264_nvenc' in r.stdout
        except (OSError, subprocess.SubprocessError) as e:
            log.debug("nvenc probe failed, assuming software encoding: %s", e)
            _has_nvenc._result = False
    return _has_nvenc._result


def _h264_encoder_args():
    """pick the lightest h264 encoder available"""
    if _has_nvenc():
        # nvenc: near-zero cpu, gpu does all the work
        return ['-c:v', 'h264_nvenc', '-preset', 'p1', '-tune', 'ull',
                '-b:v', '2M', '-maxrate', '4M', '-bufsize', '4M']
    # cpu fallback
    return ['-c:v', 'libx264', '-preset', 'ultrafast',
            '-x264-params', 'bframes=0']


# --<|||h264 encoding|||>--

def encode_h264(input_path, width=WIDTH, height=HEIGHT, crop=None, rotation=0):
    """convert any image/video to raw h264 for the device

    crop: optional (x, y, w, h) in ROTATED source pixels
    rotation: 0/90/180/270 -- applied before crop
    uses nvenc when available, libx264 ultrafast as fallback
    """
    outfile = tempfile.NamedTemporaryFile(suffix='.h264', delete=False)
    outpath = outfile.name
    outfile.close()

    # build filter chain: rotate first, then crop, then scale
    filters = []
    if rotation == 90:
        filters.append('transpose=1')  # 90 CW
    elif rotation == 180:
        filters.append('hflip,vflip')
    elif rotation == 270:
        filters.append('transpose=2')  # 90 CCW

    if crop:
        cx, cy, cw, ch = crop
        if cw > 0 and ch > 0:
            filters.append(f'crop={cw}:{ch}:{cx}:{cy}')

    filters.append(
        f'scale={width}:{height}:force_original_aspect_ratio=decrease,'
        f'pad={width}:{height}:(ow-iw)/2:(oh-ih)/2')

    cmd = ['ffmpeg', '-y', '-i', input_path,
           '-vf', ','.join(filters)]
    cmd += _h264_encoder_args()
    cmd += ['-pix_fmt', 'yuv420p', '-an', '-f', 'h264', outpath]

    try:
        result = subprocess.run(cmd, capture_output=True,
                                timeout=C.FFMPEG_ENCODE_TIMEOUT_S)
    except (OSError, subprocess.SubprocessError) as e:
        _quiet_unlink(outpath)
        log.error("ffmpeg failed to run: %s", e)
        return None
    if result.returncode != 0:
        _quiet_unlink(outpath)
        log.error("ffmpeg error: %s", result.stderr.decode(errors='replace')[:500])
        return None
    return outpath


def _quiet_unlink(path):
    """delete a file, ignoring 'already gone'"""
    with contextlib.suppress(FileNotFoundError, OSError):
        os.unlink(path)


@contextlib.contextmanager
def encoded_h264(input_path, **kwargs):
    """encode input_path to a temp .h264 and guarantee the temp is removed.

    yields the encoded path. raises EncodeError if encoding fails. if the input
    is already raw .h264 it is yielded as-is and left in place (not deleted).
    """
    if input_path.endswith('.h264'):
        yield input_path
        return
    path = encode_h264(input_path, **kwargs)
    if path is None:
        raise EncodeError(f"failed to encode {input_path}")
    try:
        yield path
    finally:
        _quiet_unlink(path)


# --<|||static content|||>--

def make_solid_jpeg(color=(0, 0, 0), width=WIDTH, height=HEIGHT):
    """generate a solid color jpeg -- no h264 encoding needed"""
    from PIL import Image
    img = Image.new('RGB', (width, height), color)
    buf = io.BytesIO()
    img.save(buf, format='JPEG', quality=85)
    return buf.getvalue()


def make_png(width=WIDTH, height=HEIGHT, color=(255, 0, 0)):
    """solid color png at device resolution"""
    from PIL import Image
    img = Image.new('RGB', (width, height), color)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


def parse_color(color_str):
    """parse a color name (see protocol.LED_COLORS, plus 'black') or hex to (r, g, b)"""
    name = color_str.lower()
    if name == 'black':
        return (0, 0, 0)
    if name in LED_COLORS:
        return LED_COLORS[name]
    # hex: 0xRRGGBB or #RRGGBB
    c = color_str.lstrip('#').replace('0x', '').replace('0X', '')
    if len(c) == 6:
        try:
            return (int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16))
        except ValueError:
            pass
    return (255, 0, 0)  # default red


# --<|||matrix rain|||>--

# monospace font candidates across common distros -- first hit wins
_MONO_FONT_CANDIDATES = (
    '/usr/share/fonts/noto/NotoSansMono-Regular.ttf',
    '/usr/share/fonts/TTF/DejaVuSansMono.ttf',
    '/usr/share/fonts/dejavu/DejaVuSansMono.ttf',
    '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
    '/usr/share/fonts/liberation/LiberationMono-Regular.ttf',
)


def _load_mono_font(ImageFont, size):
    """load a monospace truetype font, falling back to PIL's bitmap default"""
    for path in _MONO_FONT_CANDIDATES:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    log.debug("no monospace truetype font found, using PIL default")
    return ImageFont.load_default()


def generate_matrix_h264(width=WIDTH, height=HEIGHT, duration=30, fps=30,
                         ambilight=None):
    """matrix-style digital rain as h264 -- pillow frames piped to ffmpeg"""
    from PIL import Image, ImageDraw, ImageFont

    outfile = tempfile.NamedTemporaryFile(suffix='.h264', delete=False)
    outpath = outfile.name
    outfile.close()
    total_frames = duration * fps
    char_w, char_h = 10, 16
    cols = width // char_w
    rows = height // char_h

    drops = [random.randint(-rows, 0) for _ in range(cols)]
    speeds = [random.randint(1, 3) for _ in range(cols)]
    chars = "0123456789ABCDEFabcdef@#$%&*<>{}[]|/\\~"

    font = _load_mono_font(ImageFont, 14)

    cmd = ['ffmpeg', '-y', '-f', 'rawvideo', '-pix_fmt', 'rgb24',
           '-s', f'{width}x{height}', '-r', str(fps), '-i', '-']
    cmd += _h264_encoder_args()
    cmd += ['-pix_fmt', 'yuv420p', '-f', 'h264', outpath]

    # stderr -> DEVNULL: we never read it, and a full stderr pipe would deadlock
    # the frame-writing loop. rc is checked after wait() instead.
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)

    try:
        return _pump_matrix_frames(
            proc, outpath, total_frames, width, height,
            cols, rows, char_w, char_h, drops, speeds, chars, font,
            ambilight, Image, ImageDraw)
    except (BrokenPipeError, OSError, subprocess.SubprocessError) as e:
        log.error("matrix generation failed: %s", e)
        _quiet_unlink(outpath)
        return None
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=C.FFMPEG_KILL_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                proc.kill()


def _pump_matrix_frames(proc, outpath, total_frames, width, height,
                        cols, rows, char_w, char_h, drops, speeds, chars, font,
                        ambilight, Image, ImageDraw):
    for frame_num in range(total_frames):
        img = Image.new('RGB', (width, height), (0, 0, 0))
        draw = ImageDraw.Draw(img)

        for col in range(cols):
            x = col * char_w
            head_row = drops[col]

            for trail in range(rows):
                row = head_row - trail
                if 0 <= row < rows:
                    y = row * char_h
                    ch = random.choice(chars)
                    if trail == 0:
                        color = (200, 255, 200)
                    elif trail < 4:
                        color = (0, 255, 0)
                    elif trail < 12:
                        g = max(0, 200 - trail * 15)
                        color = (0, g, 0)
                    else:
                        break
                    draw.text((x, y), ch, fill=color, font=font)

            drops[col] += speeds[col]
            if drops[col] - 12 > rows:
                drops[col] = random.randint(-10, 0)
                speeds[col] = random.randint(1, 3)

        if ambilight and frame_num % 3 == 0:
            ambilight.update_frame(img.copy())

        proc.stdin.write(img.tobytes())

    proc.stdin.close()
    rc = proc.wait(timeout=C.FFMPEG_ENCODE_TIMEOUT_S)
    if rc != 0:
        log.error("matrix ffmpeg exited with code %d", rc)
        _quiet_unlink(outpath)
        return None
    return outpath
