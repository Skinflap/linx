from linx import protocol


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


def test_make_header_oversized_payload_is_safe():
    # payload longer than the 500-byte plaintext buffer must not raise
    pkt = protocol.make_header(protocol.CMD_PUSH_JPG, bytes(1000))
    assert len(pkt) == 512


def test_led_colors_table():
    assert protocol.LED_COLORS['red'] == (255, 0, 0)
    assert protocol.LED_COLORS['off'] == (0, 0, 0)
    assert 'charcoal' in protocol.LED_COLORS
