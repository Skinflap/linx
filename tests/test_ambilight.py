import pytest

from linx import ambilight

PIL = pytest.importorskip('PIL')
from PIL import Image  # noqa: E402


def test_sample_edge_colors_count():
    img = Image.new('RGB', (480, 1920), (10, 20, 30))
    colors = ambilight.sample_edge_colors(img, num_leds=60)
    assert len(colors) == 60
    assert all(c == (10, 20, 30) for c in colors)


def test_sample_edge_colors_custom_count():
    img = Image.new('RGB', (40, 160), (0, 0, 0))
    assert len(ambilight.sample_edge_colors(img, num_leds=12)) == 12


def test_sample_edge_colors_walks_the_perimeter():
    # paint the bottom row red; index 0 starts at the bottom-left and should pick it up
    img = Image.new('RGB', (40, 160), (0, 0, 0))
    for x in range(40):
        img.putpixel((x, 159), (255, 0, 0))
    colors = ambilight.sample_edge_colors(img, num_leds=8)
    assert colors[0] == (255, 0, 0)
