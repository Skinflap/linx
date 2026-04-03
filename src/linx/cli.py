"""CLI entry point for the Linx driver."""

import io
import os
import signal
import sys
import argparse

from .protocol import LCD_VID, LCD_PID, HID_VID, HID_PID, LED_VID, LED_PID, WIDTH, HEIGHT, LED_COLORS
from .device import LCDDevice, LEDDevice
from .wake import wake_from_desktop
from .ambilight import sample_edge_colors, AmbilightThread, play_h264_with_ambilight
from .content import encode_h264, generate_solid_h264, generate_matrix_h264
from .config import load_config

import usb.core


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
    p.add_argument('--grayscale', '-g', type=int, default=0, metavar='MAX',
                   help='Ambilight grayscale mode: max brightness 1-255 (e.g. -g 2)')

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

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Reload config if --config was passed
    if args.config:
        config = load_config(args.config)

    # --- LED (no LCD needed) ---
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

    # --- Wake (no LCD needed) ---
    if args.command == 'wake':
        if usb.core.find(idVendor=LCD_VID, idProduct=LCD_PID):
            print("Already in monitor mode")
        elif wake_from_desktop():
            print("Switched to monitor mode")
        else:
            print("Failed -- device not found in either mode")
        return

    # --- LCD commands ---
    lcd = LCDDevice()
    if not lcd.connect():
        print("LCD not found. Is the device plugged in?")
        print(f"  Monitor mode: {LCD_VID:04x}:{LCD_PID:04x}")
        print(f"  Desktop mode: {HID_VID:04x}:{HID_PID:04x}")
        print("  Try: linx wake")
        sys.exit(1)

    # Connect LED for ambilight if requested (--grayscale implies --ambilight)
    grayscale_max = getattr(args, 'grayscale', 0) or config['ambilight']['grayscale_max']
    use_ambilight = getattr(args, 'ambilight', False) or config['ambilight']['enabled'] or grayscale_max > 0
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
            img.save(buf, format='PNG')
            png_data = buf.getvalue()
            print(f"Pushing {args.file} ({len(png_data)} bytes, {WIDTH}x{HEIGHT})...")
            resp = lcd.push_png(png_data)
            print("Done" if resp else "No response")

        elif args.command == 'play':
            lcd.init()
            lcd.prepare_display()
            filepath = args.file
            if not filepath.endswith('.h264'):
                print(f"Encoding {filepath}...")
                filepath = encode_h264(filepath)
                if not filepath:
                    sys.exit(1)
            print(f"Streaming ({os.path.getsize(filepath)} bytes)...")
            if use_ambilight:
                play_h264_with_ambilight(lcd, led, filepath,
                                         loop=not args.no_loop,
                                         grayscale_max=grayscale_max)
            else:
                lcd.play_h264(filepath, loop=not args.no_loop)
            if not args.file.endswith('.h264'):
                os.unlink(filepath)

        elif args.command == 'color':
            lcd.init()
            lcd.prepare_display()
            if use_ambilight and args.color in LED_COLORS:
                led.set_all(*LED_COLORS[args.color])
            h264 = generate_solid_h264(args.color)
            try:
                lcd.play_h264(h264, loop=True)
            finally:
                os.unlink(h264)

        elif args.command == 'matrix':
            lcd.init()
            lcd.prepare_display()
            ambi = None
            if use_ambilight:
                ambi = AmbilightThread(led)
                ambi.start()
            h264 = generate_matrix_h264(duration=args.duration, fps=args.fps,
                                         ambilight=ambi)
            try:
                if use_ambilight:
                    play_h264_with_ambilight(lcd, led, h264, loop=True, ambi=ambi)
                else:
                    lcd.play_h264(h264, loop=True)
            finally:
                if ambi:
                    ambi.stop()
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

    finally:
        lcd.close()
        if led:
            led.off()
            led.close()


if __name__ == '__main__':
    main()
