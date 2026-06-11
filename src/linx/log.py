# centralized logging for linx -- one logger tree rooted at 'linx'
#
# the cli prints to stderr (coloured on a tty), the systemd service emits
# plain lines that journald timestamps. call setup_logging() once at an
# entry point; library code just calls get_logger(__name__).

import logging
import os
import sys

_ROOT = 'linx'
_configured = False

# ansi colours per level -- only applied when writing to a tty
_COLOURS = {
    logging.DEBUG: '\033[2m',
    logging.WARNING: '\033[33m',
    logging.ERROR: '\033[31m',
    logging.CRITICAL: '\033[1;31m',
}
_RESET = '\033[0m'


class _Formatter(logging.Formatter):
    def __init__(self, colour):
        super().__init__('%(levelname)s %(name)s: %(message)s')
        self._colour = colour

    def format(self, record):
        msg = super().format(record)
        c = _COLOURS.get(record.levelno) if self._colour else None
        return f'{c}{msg}{_RESET}' if c else msg


def setup_logging(verbose=False, stream=None):
    """configure the linx logger once -- verbose => DEBUG, else INFO.

    the LINX_LOG env var (DEBUG/INFO/WARNING/...) overrides verbose.
    idempotent: only the first call installs a handler.
    """
    global _configured
    logger = logging.getLogger(_ROOT)
    if _configured:
        return logger

    stream = stream or sys.stderr
    level = logging.DEBUG if verbose else logging.INFO
    env = os.environ.get('LINX_LOG')
    if env:
        level = getattr(logging, env.upper(), level)

    is_tty = bool(getattr(stream, 'isatty', lambda: False)())
    handler = logging.StreamHandler(stream)
    handler.setFormatter(_Formatter(colour=is_tty))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    _configured = True
    return logger


def get_logger(name=None):
    """get a child logger under the 'linx' tree"""
    if name and name != _ROOT and not name.startswith(_ROOT + '.'):
        # accept __name__ ('linx.device') or a bare label ('device')
        name = name if name.startswith(_ROOT) else f'{_ROOT}.{name}'
    return logging.getLogger(name or _ROOT)
