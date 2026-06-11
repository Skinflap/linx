"""minimal import + sanity checks -- the full suite lives alongside in test_*.py"""

from linx import constants, protocol


def test_resolution_constants():
    assert protocol.WIDTH == 480
    assert protocol.HEIGHT == 1920


def test_des_encrypt_is_block_aligned():
    out = protocol.des_encrypt(bytes(10))
    assert isinstance(out, bytes)
    assert len(out) % 8 == 0


def test_constants_are_sane():
    assert constants.DEFAULT_H264_BUF_LEN < constants.MAX_H264_BUF_LEN
    assert constants.BUFFER_TARGET_BLOCKS <= constants.BUFFER_BUSY_BLOCKS
