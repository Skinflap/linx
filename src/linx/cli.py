import argparse
import io
import os
import signal
import sys

import usb.core

from .ambilight import AmbilightThread, play_h264_with_ambilight, sample_edge_colors
from .config import load_config
from .content import encoded_h264, generate_matrix_h264
from .device import LCDDevice, LEDDevice, diagnose
from .errors import EncodeError, LinxError
from .log import get_logger, setup_logging
from .protocol import (
    HEIGHT,
    HID_PID,
    HID_VID,
    LCD_PID,
    LCD_VID,
    LED_COLORS,
    LED_PID,
    LED_VID,
    WIDTH,
)
from .wake import wake_from_desktop

log = get_logger(__name__)

SERVICE_MODES = ('matrix', 'play', 'image', 'color')


def service_argv(config):
    """translate the [service] config block into the argv the daemon should run.

    the systemd unit invokes `linx service`; this resolves [service].mode into the
    concrete play command so the exact same code path runs as a direct invocation.
    exits 2 on a misconfigured block so a broken unit fails loudly, not silently.
    """
    svc = config['service']
    mode = svc['mode']
    if mode not in SERVICE_MODES:
        print(f"Invalid [service].mode: {mode!r} (expected one of {', '.join(SERVICE_MODES)})",
              file=sys.stderr)
        sys.exit(2)
    argv = [mode]
    if mode in ('play', 'image'):
        if not svc['file']:
            print(f"[service].mode = {mode!r} requires [service].file to be set",
                  file=sys.stderr)
            sys.exit(2)
        argv.append(svc['file'])
    elif mode == 'color':
        argv.append(svc['color'])
    return argv


def main():
    config = load_config()

    parser = argparse.ArgumentParser(
        prog='linx',
        description='Linx -- Linux driver for the Lian Li 8.8" Universal Screen',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""Display: {WIDTH}x{HEIGHT} | LCD: {LCD_VID:04x}:{LCD_PID:04x} | LED: {LED_VID:04x}:{LED_PID:04x}

Examples:
  %(prog)s matrix              Matrix screensaver
  %(prog)s play video.mp4      Play a video (loops, Ctrl+C to stop)
  %(prog)s image photo.png     Display an image
  %(prog)s color blue          Solid color
  %(prog)s brightness 50       Set brightness
  %(prog)s led red             Set LED ring color
""")
    parser.add_argument('--config', '-c', metavar='FILE',
                        help='Config file path (overrides system/user configs)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose (debug) logging to stderr')
    sub = parser.add_subparsers(dest='command')

    sub.add_parser('test', help='Test connection and show firmware info')
    sub.add_parser('version', help='Show firmware version')

    p = sub.add_parser('image', help='Display an image file (PNG/JPG)')
    p.add_argument('file', help='Image file to display')
    p.add_argument('--ambilight', '-a', action='store_true',
                   help='Set LED ring to match image edges')

    p = sub.add_parser('play', help='Play a video file (any format ffmpeg supports)')
    p.add_argument('file', help='Video file to play')
    p.add_argument('--no-loop', action='store_true', help='Play once instead of looping')
    p.add_argument('--ambilight', '-a', action='store_true',
                   help='Sync LED ring to video edges')
    p.add_argument('--led-brightness', type=int, default=100, metavar='0-100',
                   help='LED ring brightness percentage (default: 100)')

    p = sub.add_parser('color', help='Display a solid color')
    p.add_argument('color', metavar='COLOR',
                   help='Color name or hex (e.g. red, 0xFF8800)')
    p.add_argument('--ambilight', '-a', action='store_true',
                   help='Set LED ring to match color')

    p = sub.add_parser('matrix', help='Matrix rain screensaver')
    p.add_argument('--ambilight', '-a', action='store_true',
                   help='Sync LED ring to screen edges')
    p.add_argument('--duration', type=int,
                   default=config['matrix']['duration'],
                   help=f'Animation duration in seconds (default: {config["matrix"]["duration"]})')
    p.add_argument('--fps', type=int,
                   default=config['matrix']['fps'],
                   help=f'Framerate (default: {config["matrix"]["fps"]})')

    p = sub.add_parser('brightness', help='Set display brightness')
    p.add_argument('level', type=int, metavar='0-100')

    sub.add_parser('stop', help='Stop video playback')
    sub.add_parser('wake', help='Wake device from desktop/standby mode')

    p = sub.add_parser('led', help='Set LED ring color')
    p.add_argument('color', metavar='COLOR',
                   help='Color name (red, green, blue, white, off, ...) or R,G,B')

    p = sub.add_parser('upload', help='Upload file to device filesystem')
    p.add_argument('file', help='Local file to upload')
    p.add_argument('target', help='Device path (e.g. /usr/data/boot.jpg)')

    sub.add_parser('service',
                   help='Run the configured [service].mode (used by linx.service)')

    args = parser.parse_args()
    setup_logging(verbose=args.verbose)
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # reload config if --config was passed
    if args.config:
        config = load_config(args.config)

    # --<|||service|||>--
    # `linx service` (the systemd entrypoint) resolves [service].mode into the real
    # command and re-parses, so the chosen mode runs identically to a direct call.
    if args.command == 'service':
        svc_argv = service_argv(config)
        if args.verbose:
            svc_argv.insert(0, '--verbose')
        log.info("service: %s", ' '.join(svc_argv))
        args = parser.parse_args(svc_argv)

    # --<|||led|||>--
    if args.command == 'led':
        led = LEDDevice()
        if not led.connect():
            print(f"LED device not found ({LED_VID:04x}:{LED_PID:04x})")
            sys.exit(1)
        if args.color in LED_COLORS:
            r, g, b = LED_COLORS[args.color]
        elif ',' in args.color:
            try:
                r, g, b = (int(x) for x in args.color.split(','))
            except ValueError:
                print(f"Invalid RGB: {args.color} (expected R,G,B e.g. 255,128,0)")
                sys.exit(1)
        else:
            print(f"Unknown color: {args.color}")
            print(f"Available: {', '.join(LED_COLORS.keys())}, or R,G,B")
            sys.exit(1)
        led.set_all(r, g, b)
        print(f"LEDs: ({r}, {g}, {b})")
        led.close()
        return

    # --<|||wake|||>--
    if args.command == 'wake':
        if usb.core.find(idVendor=LCD_VID, idProduct=LCD_PID):
            print("Already in monitor mode")
        elif wake_from_desktop():
            print("Switched to monitor mode")
        else:
            print("Failed -- device not found in either mode")
        return

    # --<|||lcd|||>--
    lcd = LCDDevice()
    if not lcd.connect():
        code, msg = diagnose()
        if code == 'ok':
            # present on the bus but connect() still failed -> claim problem
            msg = ("lcd is present but could not be claimed -- another process "
                   "(the GUI or a linx service) is holding it, or udev permissions "
                   "are missing (run over a local session, not bare SSH)")
        print(f"LCD not reachable: {msg}", file=sys.stderr)
        print(f"  Monitor mode: {LCD_VID:04x}:{LCD_PID:04x}   Desktop mode: {HID_VID:04x}:{HID_PID:04x}",
              file=sys.stderr)
        sys.exit(1)

    use_ambilight = getattr(args, 'ambilight', False) or config['ambilight']['enabled']
    led_brightness = getattr(args, 'led_brightness', 100) / 100.0
    led = None
    if use_ambilight:
        led = LEDDevice()
        if not led.connect():
            print("LED device not found -- ambilight disabled")
            led = None
            use_ambilight = False

    # systemd sends SIGTERM on stop -- hook it for playback commands so loops exit cleanly
    if args.command in ('play', 'color', 'matrix'):
        signal.signal(signal.SIGTERM, lambda sig, frame: lcd.request_stop())

    try:
        if args.command == 'test':
            lcd.init()
            ver = lcd.get_version()
            print(f"Firmware:   {ver or 'unknown'}")
            print(f"Resolution: {WIDTH}x{HEIGHT}")
            print(f"H.264 buf:  {lcd.check_h264_block()} bytes")

        elif args.command == 'version':
            ver = lcd.get_version()
            print(ver or "No response")

        elif args.command == 'image':
            from PIL import Image
            lcd.init()
            lcd.prepare_display()
            img = Image.open(args.file).convert('RGB')
            img = img.resize((WIDTH, HEIGHT), Image.LANCZOS)
            if use_ambilight:
                colors = sample_edge_colors(img)
                led.set_leds(colors)
            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=95)
            jpg_data = buf.getvalue()
            print(f"Pushing {args.file} ({len(jpg_data)} bytes, {WIDTH}x{HEIGHT})...")
            from .protocol import CMD_PUSH_JPG
            resp = lcd.push_image(jpg_data, CMD_PUSH_JPG)
            print("Done" if resp else "No response")

        elif args.command == 'play':
            lcd.init()
            lcd.prepare_display()
            if not args.file.endswith('.h264'):
                print(f"Encoding {args.file}...")
            # context manager guarantees the temp .h264 is removed even if
            # streaming raises (e.g. device unplugged mid-play)
            with encoded_h264(args.file) as filepath:
                print(f"Streaming ({os.path.getsize(filepath)} bytes)...")
                if use_ambilight:
                    play_h264_with_ambilight(lcd, led, filepath,
                                             loop=not args.no_loop,
                                             brightness=led_brightness)
                else:
                    lcd.play_h264(filepath, loop=not args.no_loop)

        elif args.command == 'color':
            lcd.init()
            lcd.prepare_display()
            from .content import make_solid_jpeg, parse_color
            from .protocol import CMD_PUSH_JPG
            rgb = parse_color(args.color)
            if use_ambilight and led:
                led.set_all(*rgb)  # works for hex too, not just named colors
            jpg = make_solid_jpeg(color=rgb)
            lcd.push_image(jpg, CMD_PUSH_JPG)
            print(f"Color: {args.color}")

        elif args.command == 'matrix':
            lcd.init()
            lcd.prepare_display()
            ambi = None
            if use_ambilight:
                ambi = AmbilightThread(led)
                ambi.start()
            h264 = generate_matrix_h264(duration=args.duration, fps=args.fps,
                                         ambilight=ambi)
            if not h264:
                if ambi:
                    ambi.stop()
                raise EncodeError("matrix generation failed")
            try:
                if use_ambilight:
                    play_h264_with_ambilight(lcd, led, h264, loop=True, ambi=ambi)
                else:
                    lcd.play_h264(h264, loop=True)
            finally:
                if ambi:
                    ambi.stop()
                if os.path.exists(h264):
                    os.unlink(h264)

        elif args.command == 'brightness':
            lcd.set_brightness(args.level)
            print(f"Brightness: {args.level}")

        elif args.command == 'stop':
            lcd.stop_play()
            lcd.clear_layers()
            print("Stopped")

        elif args.command == 'upload':
            with open(args.file, 'rb') as f:
                data = f.read()
            print(f"Uploading {len(data)} bytes to {args.target}...")
            resp = lcd.upload_file(data, args.target)
            print("Done" if resp else "No response")

    except KeyboardInterrupt:
        lcd.request_stop()
    except LinxError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        lcd.close()
        if led:
            led.off()
            led.close()


if __name__ == '__main__':
    main()
