"""Content generation -- ffmpeg encoding, matrix rain, solid colors, PNGs."""

import io
import os
import random
import subprocess
import tempfile

from .protocol import WIDTH, HEIGHT


def encode_h264(input_path, width=WIDTH, height=HEIGHT):
    """Convert any image/video to raw H.264 for the device.

    Encoding matches L-Connect 3: libx264, no B-frames, ultrafast preset.
    """
    outfile = tempfile.NamedTemporaryFile(suffix='.h264', delete=False)
    outpath = outfile.name
    outfile.close()
    result = subprocess.run([
        'ffmpeg', '-y', '-i', input_path,
        '-vf', f'scale={width}:{height}:force_original_aspect_ratio=decrease,'
               f'pad={width}:{height}:(ow-iw)/2:(oh-ih)/2',
        '-vcodec', 'libx264', '-x264opts', 'bframes=0',
        '-threads', '4', '-preset', 'ultrafast',
        '-pix_fmt', 'yuv420p', '-an',
        '-f', 'h264', outpath
    ], capture_output=True)
    if result.returncode != 0:
        print(f"FFmpeg error: {result.stderr.decode()[:500]}")
        os.unlink(outpath)
        return None
    return outpath


def generate_solid_h264(color='red', width=WIDTH, height=HEIGHT, duration=5, fps=30):
    """Generate a solid color H.264 test clip."""
    colors = {
        'red': '0xFF0000', 'green': '0x00FF00', 'blue': '0x0000FF',
        'white': '0xFFFFFF', 'black': '0x000000', 'cyan': '0x00FFFF',
        'magenta': '0xFF00FF', 'yellow': '0xFFFF00',
    }
    c = colors.get(color, color)
    outfile = tempfile.NamedTemporaryFile(suffix='.h264', delete=False)
    outpath = outfile.name
    outfile.close()
    subprocess.run([
        'ffmpeg', '-y', '-f', 'lavfi',
        '-i', f'color=c={c}:s={width}x{height}:d={duration}:r={fps}',
        '-vcodec', 'libx264', '-x264opts', 'bframes=0',
        '-threads', '4', '-preset', 'ultrafast',
        '-pix_fmt', 'yuv420p',
        '-f', 'h264', outpath
    ], capture_output=True, check=True)
    return outpath


def generate_matrix_h264(width=WIDTH, height=HEIGHT, duration=30, fps=30,
                         ambilight=None):
    """Generate a Matrix-style digital rain animation as H.264.

    Renders frames with Pillow, pipes to ffmpeg for encoding.
    If `ambilight` is an AmbilightThread, feeds frames to it for LED sync.
    """
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

    try:
        font = ImageFont.truetype("/usr/share/fonts/noto/NotoSansMono-Regular.ttf", 14)
    except (OSError, IOError):
        try:
            font = ImageFont.truetype("/usr/share/fonts/TTF/DejaVuSansMono.ttf", 14)
        except (OSError, IOError):
            font = ImageFont.load_default()

    proc = subprocess.Popen([
        'ffmpeg', '-y', '-f', 'rawvideo', '-pix_fmt', 'rgb24',
        '-s', f'{width}x{height}', '-r', str(fps), '-i', '-',
        '-vcodec', 'libx264', '-x264opts', 'bframes=0',
        '-threads', '4', '-preset', 'ultrafast',
        '-pix_fmt', 'yuv420p',
        '-f', 'h264', outpath
    ], stdin=subprocess.PIPE, stderr=subprocess.PIPE)

    print(f"Generating {total_frames} frames ({duration}s at {fps}fps)...")
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

        # Feed frame to ambilight if active
        if ambilight and frame_num % 3 == 0:
            ambilight.update_frame(img.copy())

        proc.stdin.write(img.tobytes())
        if (frame_num + 1) % (fps * 5) == 0:
            print(f"  {frame_num + 1}/{total_frames} frames...")

    proc.stdin.close()
    proc.wait()
    size = os.path.getsize(outpath)
    print(f"Done: {size / 1024 / 1024:.1f} MB")
    return outpath


def make_png(width=WIDTH, height=HEIGHT, color=(255, 0, 0)):
    """Generate a solid color PNG at device resolution."""
    from PIL import Image
    img = Image.new('RGB', (width, height), color)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()
