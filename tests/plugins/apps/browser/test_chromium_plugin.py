from dissect.target.plugins.apps.browser import chromium
from tests._utils import absolute_path


def test_chromium_downloads(target_win, fs_win, tmp_path, target_win_users):
    __setup(target_win, fs_win, tmp_path, target_win_users, "History")
    records = list(target_win.chromium.downloads())
    assert len(records) == 1


def test_chromium_extensions(target_win, fs_win, tmp_path, target_win_users):
    __setup(target_win, fs_win, tmp_path, target_win_users, "History")
    records = list(target_win.chromium.extensions())
    assert len(records) == 4


def test_chromium_history(target_win, fs_win, tmp_path, target_win_users):
    __setup(target_win, fs_win, tmp_path, target_win_users, "History")
    records = list(target_win.chromium.history())
    assert len(records) == 5


def test_chromium_cookies(target_win, fs_win, tmp_path, target_win_users):
    __setup(target_win, fs_win, tmp_path, target_win_users, "Cookies")
    records = list(target_win.chromium.cookies())
    record_names = sorted([*map(lambda c: c.name, records)])
    assert record_names == ["pl", "ssa-did", "ssa-sid", "tbb", "twk-theme"]


def __setup(target_win, fs_win, tmp_path, target_win_users, db) -> None:
    chromium_db = absolute_path(f"_data/plugins/apps/browser/chromium/{db}.sqlite")
    chromium_prefs = absolute_path("_data/plugins/apps/browser/chromium/windows/Preferences")
    chromium_sec_prefs = absolute_path("_data/plugins/apps/browser/chromium/windows/Secure Preferences")

    user = target_win_users.user_details.find(username="John")
    webcache_dir = user.home_path.joinpath("AppData/Local/Chromium/User Data/Default")
    webcache_file = webcache_dir.joinpath(db)
    extensions_pref_file = webcache_dir.joinpath("Preferences")
    extensions_sec_pref_file = webcache_dir.joinpath("Secure Preferences")

    # drop C:/
    webcache_dir = str(webcache_dir)[3:]
    webcache_file = str(webcache_file)[3:]
    extensions_pref_file = str(extensions_pref_file)[3:]
    extensions_sec_pref_file = str(extensions_sec_pref_file)[3:]

    fs_win.map_dir("Users\\John", tmp_path)
    fs_win.map_file(webcache_file, chromium_db)
    fs_win.map_file(extensions_pref_file, chromium_prefs)
    fs_win.map_file(extensions_sec_pref_file, chromium_sec_prefs)

    target_win.add_plugin(chromium.ChromiumPlugin)
