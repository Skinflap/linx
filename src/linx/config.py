import copy
import tomllib
from pathlib import Path

from .log import get_logger

log = get_logger(__name__)

SYSTEM_CONFIG = Path('/etc/linx.conf')
USER_CONFIG = Path.home() / '.config' / 'linx' / 'config.toml'

DEFAULTS = {
    'display': {
        'brightness': 80,
        'rotation': 0,
    },
    'matrix': {
        'duration': 60,
        'fps': 30,
    },
    'ambilight': {
        'enabled': False,
    },
    'service': {
        'mode': 'matrix',
        'file': '',
        'color': 'red',
    },
    'gui': {
        'mode': 0,
        'image_path': '',
        'video_path': '',
        'color': 0,
        'loop': True,
        'image_rotation': 0,
    },
}


def _deep_merge(base, override):
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def load_config(path=None):
    """priority: explicit path > user config > system config > defaults"""
    config = copy.deepcopy(DEFAULTS)  # deep copy so callers can mutate freely

    paths = [SYSTEM_CONFIG, USER_CONFIG]
    if path:
        paths.append(Path(path))

    for cfg_path in paths:
        if not cfg_path.exists():
            continue
        try:
            with open(cfg_path, 'rb') as f:
                config = _deep_merge(config, tomllib.load(f))
        except tomllib.TOMLDecodeError as e:
            log.warning("ignoring malformed config %s: %s", cfg_path, e)
        except OSError as e:
            log.warning("could not read config %s: %s", cfg_path, e)

    return config


# --<|||toml emitting|||>--
# small correct emitter for the flat section -> key -> scalar/array config we
# use. proper escaping (the old hand-rolled version corrupted strings with
# quotes/newlines), and it preserves unknown sections/keys on save.

def _toml_escape(s):
    out = ['"']
    for ch in s:
        if ch == '\\':
            out.append('\\\\')
        elif ch == '"':
            out.append('\\"')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\t':
            out.append('\\t')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\r':
            out.append('\\r')
        elif ord(ch) < 0x20:
            out.append(f'\\u{ord(ch):04X}')
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _toml_value(val):
    if isinstance(val, bool):          # before int -- bool is an int subclass
        return 'true' if val else 'false'
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        return repr(val)
    if isinstance(val, str):
        return _toml_escape(val)
    if isinstance(val, (list, tuple)):
        return '[' + ', '.join(_toml_value(v) for v in val) + ']'
    raise TypeError(f'unserializable TOML value: {val!r}')


def save_config(config, path=None):
    """write values that differ from the defaults to the user config.

    unknown sections/keys (not present in DEFAULTS) are preserved verbatim.
    """
    target = Path(path) if path else USER_CONFIG
    target.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    for section, values in config.items():
        if not isinstance(values, dict):
            continue
        defaults = DEFAULTS.get(section, {})
        body = []
        for key, val in values.items():
            if key in defaults and val == defaults[key]:
                continue  # omit unchanged defaults to keep the file minimal
            try:
                body.append(f'{key} = {_toml_value(val)}')
            except TypeError:
                log.warning("skipping unserializable config %s.%s (%r)", section, key, val)
        if body:
            lines.append(f'[{section}]')
            lines.extend(body)
            lines.append('')

    target.write_text('\n'.join(lines) + '\n' if lines else '')
