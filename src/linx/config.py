"""Configuration loading -- merges system and user TOML configs."""

import os
import tomllib
from pathlib import Path

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
        'grayscale_max': 0,
    },
    'service': {
        'mode': 'matrix',
        'file': '',
        'color': 'red',
    },
}


def _deep_merge(base, override):
    """Merge override into base, recursing into dicts."""
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def load_config(path=None):
    """Load config from system + user files, with optional explicit path override.

    Priority (highest wins): explicit path > user config > system config > defaults.
    Missing files are silently skipped -- everything has defaults.
    """
    config = dict(DEFAULTS)

    for cfg_path in [SYSTEM_CONFIG, USER_CONFIG]:
        if cfg_path.exists():
            try:
                with open(cfg_path, 'rb') as f:
                    config = _deep_merge(config, tomllib.load(f))
            except (tomllib.TOMLDecodeError, OSError) as e:
                print(f"Warning: failed to load {cfg_path}: {e}")

    if path:
        p = Path(path)
        if p.exists():
            try:
                with open(p, 'rb') as f:
                    config = _deep_merge(config, tomllib.load(f))
            except (tomllib.TOMLDecodeError, OSError) as e:
                print(f"Warning: failed to load {p}: {e}")

    return config


def save_config(config, path=None):
    """Write config dict as TOML to the user config file.

    Only writes sections/keys that differ from DEFAULTS.
    """
    target = Path(path) if path else USER_CONFIG
    target.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    for section, defaults in DEFAULTS.items():
        if section not in config:
            continue
        section_lines = []
        for key, default_val in defaults.items():
            val = config[section].get(key, default_val)
            if val != default_val:
                if isinstance(val, bool):
                    section_lines.append(f'{key} = {"true" if val else "false"}')
                elif isinstance(val, int):
                    section_lines.append(f'{key} = {val}')
                elif isinstance(val, str):
                    section_lines.append(f'{key} = "{val}"')
        if section_lines:
            lines.append(f'[{section}]')
            lines.extend(section_lines)
            lines.append('')

    with open(target, 'w') as f:
        f.write('\n'.join(lines) + '\n' if lines else '')
