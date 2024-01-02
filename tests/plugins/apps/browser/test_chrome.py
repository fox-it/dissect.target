from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.browser import chrome
from tests._utils import absolute_path


def test_chrome(target_win: Target, fs_win: VirtualFilesystem, tmp_path: str, target_win_users: Target):
    __setup(target_win, fs_win, tmp_path, target_win_users)
    records = list(target_win.chrome.downloads())
    assert len(records) == 1
    records = list(target_win.chrome.extensions())
    assert len(records) == 8
    records = list(target_win.chrome.history())
    assert len(records) == 5


def __setup(target_win: Target, fs_win: VirtualFilesystem, tmp_path: str, target_win_users: Target) -> None:
    chrome_db = absolute_path("_data/plugins/apps/browser/chrome/History.sqlite")
    chrome_prefs = absolute_path("_data/plugins/apps/browser/chrome/windows/Preferences")
    chrome_sec_prefs = absolute_path("_data/plugins/apps/browser/chrome/windows/Secure Preferences")

    user = target_win_users.user_details.find(username="John")
    webcache_dir = user.home_path.joinpath("AppData/Local/Google/Chrome/User Data/Default")
    webcache_file = webcache_dir.joinpath("History")
    extensions_pref_file = webcache_dir.joinpath("Preferences")
    extensions_sec_pref_file = webcache_dir.joinpath("Secure Preferences")

    # drop C:/
    webcache_dir = str(webcache_dir)[3:]
    webcache_file = str(webcache_file)[3:]
    extensions_pref_file = str(extensions_pref_file)[3:]
    extensions_sec_pref_file = str(extensions_sec_pref_file)[3:]

    fs_win.map_dir("Users\\John", tmp_path)
    fs_win.map_file(webcache_file, chrome_db)
    fs_win.map_file(extensions_pref_file, chrome_prefs)
    fs_win.map_file(extensions_sec_pref_file, chrome_sec_prefs)

    target_win.add_plugin(chrome.ChromePlugin)
