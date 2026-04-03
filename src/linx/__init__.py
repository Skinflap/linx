"""Linx -- Linux driver for the Lian Li 8.8" Universal Screen."""

__version__ = "1.0.0"

from .protocol import WIDTH, HEIGHT
from .device import LCDDevice, LEDDevice
from .wake import wake_from_desktop
