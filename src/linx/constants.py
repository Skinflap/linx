# tunable constants -- usb endpoints, timeouts, polling intervals, buffers
#
# these were previously scattered as magic numbers across device/wake/
# content/ambilight. collected here so the driver's timing behaviour is
# visible and tunable in one place. values are tuned for the lian li 8.8"
# screen over usb 2.0.

# --<|||usb endpoints|||>--
EP_OUT = 0x01            # bulk/interrupt out
EP_IN = 0x81            # bulk/interrupt in

# --<|||usb i/o timeouts (milliseconds)|||>--
READ_FLUSH_MS = 10      # short drain of stale read data
READ_RESP_MS = 2000     # waiting for a command response
WRITE_BASE_MS = 2000    # base write timeout
WRITE_PER_BYTES = 500   # +1ms of write timeout per this many bytes
LED_WRITE_MS = 2000
LED_READ_MS = 500

# --<|||h264 streaming flow control|||>--
DEFAULT_H264_BUF_LEN = 202752         # fallback chunk size until the device reports its own
MAX_H264_BUF_LEN = 4 * 1024 * 1024    # sanity ceiling on a device-reported buffer size
CHUNK_DELAY_S = 0.03                  # pacing between chunk writes
BUFFER_POLL_S = 0.05                  # QueryBlock poll interval while the buffer is full
BUFFER_POLL_MAX = 200                 # max polls (~10s) before giving up
BUFFER_BUSY_BLOCKS = 3                # a reported block-count above this => wait for room
BUFFER_TARGET_BLOCKS = 2             # wait until the block-count drops to this

# --<|||wake / mode switch|||>--
WAKE_POLL_S = 0.5
WAKE_POLL_COUNT = 20    # ~10s for the TI MCU to enumerate after SetMonitorMode

# --<|||subprocess (ffmpeg)|||>--
FFMPEG_PROBE_TIMEOUT_S = 5      # encoder-capability probe
FFMPEG_ENCODE_TIMEOUT_S = 180   # one-shot encode of an image/video
FFMPEG_KILL_TIMEOUT_S = 2       # grace period after terminate() before kill()

# --<|||ambilight|||>--
AMBI_FRAME_WAIT_S = 1.0         # idle wakeup interval for the led thread
AMBI_DECODER_RESTART_S = 0.5    # pause before restarting a dead decoder
AMBI_SAMPLE_DIVISOR = 4         # decode at WIDTH/N x HEIGHT/N for edge sampling
AMBI_SAMPLE_FPS = 10
