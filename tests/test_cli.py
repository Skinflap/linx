import pytest

from linx import cli
from linx.config import load_config


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    """defaults-only config, isolated from the real system/user files"""
    from linx import config
    monkeypatch.setattr(config, 'SYSTEM_CONFIG', tmp_path / 'system.conf')
    monkeypatch.setattr(config, 'USER_CONFIG', tmp_path / 'user.toml')
    return load_config()


def test_default_mode_is_matrix(cfg):
    assert cli.service_argv(cfg) == ['matrix']


def test_color_mode_passes_color(cfg):
    cfg['service']['mode'] = 'color'
    cfg['service']['color'] = 'blue'
    assert cli.service_argv(cfg) == ['color', 'blue']


def test_play_mode_passes_file(cfg):
    cfg['service']['mode'] = 'play'
    cfg['service']['file'] = '/srv/loop.mp4'
    assert cli.service_argv(cfg) == ['play', '/srv/loop.mp4']


def test_image_mode_passes_file(cfg):
    cfg['service']['mode'] = 'image'
    cfg['service']['file'] = '/srv/wall.png'
    assert cli.service_argv(cfg) == ['image', '/srv/wall.png']


@pytest.mark.parametrize('mode', ['play', 'image'])
def test_file_mode_without_file_exits(cfg, mode):
    cfg['service']['mode'] = mode
    cfg['service']['file'] = ''
    with pytest.raises(SystemExit) as exc:
        cli.service_argv(cfg)
    assert exc.value.code == 2


def test_unknown_mode_exits(cfg):
    cfg['service']['mode'] = 'service'  # the old never-existed verb -> loud fail
    with pytest.raises(SystemExit) as exc:
        cli.service_argv(cfg)
    assert exc.value.code == 2
