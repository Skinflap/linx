from linx import content


def test_parse_color_names():
    assert content.parse_color('red') == (255, 0, 0)
    assert content.parse_color('GREEN') == (0, 255, 0)
    assert content.parse_color('black') == (0, 0, 0)
    # sourced from the single protocol.LED_COLORS table, not a local copy
    assert content.parse_color('charcoal') == (138, 146, 164)


def test_parse_color_hex():
    assert content.parse_color('0x00FF80') == (0, 255, 128)
    assert content.parse_color('#FF8800') == (255, 136, 0)


def test_parse_color_invalid_defaults_to_red():
    assert content.parse_color('not-a-color') == (255, 0, 0)
    assert content.parse_color('0xZZZZZZ') == (255, 0, 0)


def test_encoded_h264_passthrough_for_raw(tmp_path):
    # a .h264 input is yielded as-is and NOT deleted
    raw = tmp_path / 'clip.h264'
    raw.write_bytes(b'\x00\x00\x01')
    with content.encoded_h264(str(raw)) as path:
        assert path == str(raw)
    assert raw.exists()  # passthrough must not delete the caller's file
