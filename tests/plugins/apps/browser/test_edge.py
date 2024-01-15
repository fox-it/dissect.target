import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.browser import edge
from tests._utils import absolute_path


def test_edge_downloads(target_win: Target, fs_win: VirtualFilesystem, tmp_path: str, target_win_users: Target) -> None:
    setup_edge(target_win, fs_win, tmp_path, target_win_users)
    records = list(target_win.edge.downloads())
    assert len(records) == 2


def test_edge_extensions(
    target_win: Target, fs_win: VirtualFilesystem, tmp_path: str, target_win_users: Target
) -> None:
    setup_edge(target_win, fs_win, tmp_path, target_win_users)
    records = list(target_win.edge.extensions())
    assert len(records) == 39


def test_edge_history(target_win: Target, fs_win: VirtualFilesystem, tmp_path: str, target_win_users: Target) -> None:
    setup_edge(target_win, fs_win, tmp_path, target_win_users)
    records = list(target_win.edge.history())
    assert len(records) == 45


@pytest.fixture
def setup_edge(target_win: Target, fs_win: VirtualFilesystem, tmp_path: str, target_win_users: Target) -> None:
    edge_db = absolute_path("_data/plugins/apps/browser/edge/History.sqlite")
    edge_prefs = absolute_path("_data/plugins/apps/browser/edge/windows/Preferences")
    edge_sec_prefs = absolute_path("_data/plugins/apps/browser/edge/windows/Secure Preferences")

    user = target_win_users.user_details.find(username="John")
    webcache_dir = user.home_path.joinpath("AppData/Local/Microsoft/Edge/User Data/Default")
    webcache_file = webcache_dir.joinpath("History")
    extensions_pref_file = webcache_dir.joinpath("Preferences")
    extensions_sec_pref_file = webcache_dir.joinpath("Secure Preferences")

    # drop C:/
    webcache_dir = str(webcache_dir)[3:]
    webcache_file = str(webcache_file)[3:]
    extensions_pref_file = str(extensions_pref_file)[3:]
    extensions_sec_pref_file = str(extensions_sec_pref_file)[3:]

    fs_win.map_dir("Users\\John", tmp_path)
    fs_win.map_file(webcache_file, edge_db)
    fs_win.map_file(extensions_pref_file, edge_prefs)
    fs_win.map_file(extensions_sec_pref_file, edge_sec_prefs)

    target_win.add_plugin(edge.EdgePlugin)
