import pytest

from linx import config


@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    """point system/user config at throwaway paths so tests can't touch the real ones"""
    monkeypatch.setattr(config, 'SYSTEM_CONFIG', tmp_path / 'system.conf')
    monkeypatch.setattr(config, 'USER_CONFIG', tmp_path / 'user.toml')
    return tmp_path


def test_load_returns_deep_copy_of_defaults(isolated_config):
    cfg = config.load_config()
    cfg['display']['brightness'] = 1  # mutate the result
    # the module defaults must be untouched
    assert config.DEFAULTS['display']['brightness'] == 80


def test_all_defaults_write_empty_file(isolated_config):
    config.save_config(config.load_config())
    assert (isolated_config / 'user.toml').read_text().strip() == ''


def test_roundtrip_preserves_nondefault_values(isolated_config):
    cfg = config.load_config()
    cfg['display']['brightness'] = 42
    cfg['gui']['loop'] = False
    config.save_config(cfg)

    loaded = config.load_config()
    assert loaded['display']['brightness'] == 42
    assert loaded['gui']['loop'] is False
    # an untouched default is still the default
    assert loaded['matrix']['fps'] == 30


def test_string_escaping_survives_roundtrip(isolated_config):
    nasty = 'a "quoted" path\nwith\ttabs and \\ backslash'
    cfg = config.load_config()
    cfg['service']['file'] = nasty
    config.save_config(cfg)
    assert config.load_config()['service']['file'] == nasty


def test_unknown_sections_are_preserved(isolated_config):
    cfg = config.load_config()
    cfg['plugins'] = {'custom': 'value', 'count': 3}
    config.save_config(cfg)
    loaded = config.load_config()
    assert loaded['plugins'] == {'custom': 'value', 'count': 3}


def test_malformed_config_is_ignored(isolated_config, caplog):
    (isolated_config / 'user.toml').write_text('this is = = not valid toml [[[')
    cfg = config.load_config()  # must not raise
    assert cfg['display']['brightness'] == 80  # falls back to defaults
