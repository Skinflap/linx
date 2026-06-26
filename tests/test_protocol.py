import struct

from Crypto.Cipher import DES

from linx import protocol


def _decrypt_header(pkt):
    """recover the 500-byte plaintext command buffer from a built packet"""
    cipher = DES.new(protocol.DES_KEY, DES.MODE_CBC, iv=protocol.DES_KEY)
    return cipher.decrypt(bytes(pkt[:504]))


def test_des_encrypt_pads_to_block():
    # 10 bytes -> padded to 16; always a multiple of the 8-byte DES block
    assert len(protocol.des_encrypt(bytes(10))) == 16
    assert len(protocol.des_encrypt(b'')) == 8
    assert len(protocol.des_encrypt(bytes(16))) == 24  # full block => +8 pkcs7


def test_des_encrypt_is_deterministic():
    # fixed key+iv => same plaintext always encrypts identically
    assert protocol.des_encrypt(b'hello') == protocol.des_encrypt(b'hello')


def test_make_header_shape():
    pkt = protocol.make_header(protocol.CMD_GET_VER)
    assert len(pkt) == 512
    # magic trailer the firmware expects
    assert pkt[510] == 0xA1
    assert pkt[511] == 0x1A


def test_make_header_places_cmd_and_payload():
    # the cmd byte and a big-endian length payload (as device.push_image frames it)
    # must land at buf[0] and buf[8:] of the decrypted plaintext
    pkt = protocol.make_header(protocol.CMD_PUSH_JPG, struct.pack('>I', 123456))
    buf = _decrypt_header(pkt)
    assert buf[0] == protocol.CMD_PUSH_JPG
    assert buf[2] == 0x1A and buf[3] == 0x6D  # firmware magic
    assert int.from_bytes(buf[8:12], 'big') == 123456


def test_make_header_oversized_payload_is_safe():
    # payload longer than the 500-byte plaintext buffer must not raise, and is
    # truncated to the 492 bytes that fit after the 8-byte prefix
    payload = bytes(range(256)) * 4  # 1024 bytes
    pkt = protocol.make_header(protocol.CMD_PUSH_JPG, payload)
    assert len(pkt) == 512
    assert _decrypt_header(pkt)[8:500] == payload[:492]


def test_led_colors_table():
    assert protocol.LED_COLORS['red'] == (255, 0, 0)
    assert protocol.LED_COLORS['off'] == (0, 0, 0)
    assert 'charcoal' in protocol.LED_COLORS
