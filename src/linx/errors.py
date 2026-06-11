# typed exceptions -- let callers tell "no response, that's fine" apart from
# "the device fell off the bus" apart from "ffmpeg failed".

class LinxError(Exception):
    """base for every error raised by linx"""


class DeviceError(LinxError):
    """a usb device operation failed"""


class DeviceNotFound(DeviceError):
    """the device could not be located on the bus"""


class DeviceDisconnected(DeviceError):
    """the device stopped responding mid-operation (write failed + reconnect failed)"""


class DeviceTimeout(DeviceError):
    """an expected response never arrived within the timeout"""


class EncodeError(LinxError):
    """ffmpeg failed to encode/generate content"""
