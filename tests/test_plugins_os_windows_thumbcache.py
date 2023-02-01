from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from dissect.thumbcache.exceptions import UnknownThumbnailTypeError

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugins.os.windows.thumbcache import ThumbcachePlugin


def create_user_data_paths(target_win: Target, tmp_path: Path) -> Path:
    """Add the explorer userdata path to ``target_win``.

    Returns: the path of created directory.
    """

    mocked_user_details = Mock()
    mocked_user = Mock()
    mocked_user.home_path = tmp_path
    mocked_user_details.all_with_home.return_value = [mocked_user]
    target_win.user_details = mocked_user_details

    explorer_dir = tmp_path / "appdata/local/microsoft/windows/explorer/"
    explorer_dir.mkdir(parents=True)

    return explorer_dir


def test_thumbcache_unsupported(target_win: Target, tmp_path: Path):
    with pytest.raises(UnsupportedPluginError):
        target_win.add_plugin(ThumbcachePlugin)

    create_user_data_paths(target_win, tmp_path)

    # Raises an error as there are no *_idx files.
    with pytest.raises(UnsupportedPluginError):
        target_win.add_plugin(ThumbcachePlugin)


def test_thumbcach_supported(target_win: Target, tmp_path: Path):
    explorer_dir = create_user_data_paths(target_win, tmp_path)

    (explorer_dir / "thumbcache_idx.db").touch()
    target_win.add_plugin(ThumbcachePlugin)


def test_thumbcache_dump_entry(target_win: Target, tmp_path: Path):
    create_user_data_paths(target_win, tmp_path)
    plugin = ThumbcachePlugin(target_win)
    with patch("dissect.target.plugins.os.windows.thumbcache.dump_entry_data_through_index") as mocked_dump:
        list(plugin._parse_thumbcache(None, None, Mock()))
        mocked_dump.assert_called_once()


def test_thumbcache_create_flow(target_win: Target, tmp_path: Path):
    create_user_data_paths(target_win, tmp_path)
    with patch("dissect.target.plugins.os.windows.thumbcache.Thumbcache") as mocked_thumbcache:
        plugin = ThumbcachePlugin(target_win)
        plugin._create_entries = Mock(return_value=["Hello"])
        assert len(list(plugin._parse_thumbcache(None, None, None))) == 1
        mocked_thumbcache.assert_called_once()


def test_thumbcache_unknown_exception(target_win: Target, tmp_path: Path):
    create_user_data_paths(target_win, tmp_path)
    plugin = ThumbcachePlugin(target_win)
    logger = Mock()
    target_win.log = logger

    with patch("dissect.target.plugins.os.windows.thumbcache.Thumbcache"):
        plugin._create_entries = Mock(side_effect=[FileNotFoundError])
        list(plugin._parse_thumbcache(None, None, None))
        logger.critical.assert_called_once()


def test_thumbcache_thumbcache_exception(target_win: Target, tmp_path: Path):
    create_user_data_paths(target_win, tmp_path)
    plugin = ThumbcachePlugin(target_win)
    logger = Mock()
    target_win.log = logger

    with patch("dissect.target.plugins.os.windows.thumbcache.Thumbcache"):
        plugin._create_entries = Mock(side_effect=[UnknownThumbnailTypeError])
        list(plugin._parse_thumbcache(None, None, None))
        logger.error.assert_called_once()
