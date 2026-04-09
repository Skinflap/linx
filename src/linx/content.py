
import io
import os
import random
import shutil
import subprocess
import tempfile

from .protocol import WIDTH, HEIGHT


# --<|||encoder detection|||>--

def _has_nvenc():
    """check if h264_nvenc is available -- cached"""
    if not hasattr(_has_nvenc, '_result'):
        try:
            r = subprocess.run(
                ['ffmpeg', '-hide_banner', '-encoders'],
                capture_output=True, timeout=5)
            _has_nvenc._result = b'h264_nvenc' in r.stdout
        except Exception:
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

    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        print(f"ffmpeg error: {result.stderr.decode()[:500]}")
        os.unlink(outpath)
        return None
    return outpath


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
    """parse color name or hex to (r, g, b) tuple"""
    colors = {
        'red': (255, 0, 0), 'green': (0, 255, 0), 'blue': (0, 0, 255),
        'white': (255, 255, 255), 'black': (0, 0, 0), 'cyan': (0, 255, 255),
        'magenta': (255, 0, 255), 'yellow': (255, 255, 0),
    }
    if color_str.lower() in colors:
        return colors[color_str.lower()]
    # hex: 0xRRGGBB or #RRGGBB
    c = color_str.lstrip('#').replace('0x', '').replace('0X', '')
    if len(c) == 6:
        return (int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16))
    return (255, 0, 0)  # default red


def generate_solid_h264(color='red', width=WIDTH, height=HEIGHT, duration=5, fps=30):
    """solid color h264 clip -- only used for looping display via h264 pipeline"""
    c = color if color.startswith('0x') or color.startswith('#') else {
        'red': '0xFF0000', 'green': '0x00FF00', 'blue': '0x0000FF',
        'white': '0xFFFFFF', 'black': '0x000000', 'cyan': '0x00FFFF',
        'magenta': '0xFF00FF', 'yellow': '0xFFFF00',
    }.get(color, color)

    outfile = tempfile.NamedTemporaryFile(suffix='.h264', delete=False)
    outpath = outfile.name
    outfile.close()

    cmd = ['ffmpeg', '-y', '-f', 'lavfi',
           '-i', f'color=c={c}:s={width}x{height}:d={duration}:r={fps}']
    cmd += _h264_encoder_args()
    cmd += ['-pix_fmt', 'yuv420p', '-f', 'h264', outpath]

    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        os.unlink(outpath)
        return None
    return outpath


# --<|||matrix rain|||>--

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

    # NOTE arch-specific font paths, falls back to default on other distros
    try:
        font = ImageFont.truetype("/usr/share/fonts/noto/NotoSansMono-Regular.ttf", 14)
    except (OSError, IOError):
        try:
            font = ImageFont.truetype("/usr/share/fonts/TTF/DejaVuSansMono.ttf", 14)
        except (OSError, IOError):
            font = ImageFont.load_default()

    cmd = ['ffmpeg', '-y', '-f', 'rawvideo', '-pix_fmt', 'rgb24',
           '-s', f'{width}x{height}', '-r', str(fps), '-i', '-']
    cmd += _h264_encoder_args()
    cmd += ['-pix_fmt', 'yuv420p', '-f', 'h264', outpath]

    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE)

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
    proc.wait()
    size = os.path.getsize(outpath)
    return outpath
