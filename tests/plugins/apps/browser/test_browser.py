import gzip
import tempfile

from dissect.target.plugins.apps.browser import (
    chrome,
    chromium,
    edge,
    firefox,
    iexplore,
)
from tests._utils import absolute_path


def test_iexplore_plugin(target_win, fs_win, tmp_path, target_win_users):
    cache_archive = absolute_path("_data/plugins/apps/browser/iexplore/WebCacheV01.dat.gz")

    with tempfile.NamedTemporaryFile(dir=tmp_path, delete=False) as tf:
        with gzip.GzipFile(cache_archive, "rb") as f:
            tf.write(f.read())
        tf.flush()
        tf.close()

        user = target_win_users.user_details.find(username="John")
        webcache_dir = user.home_path.joinpath("AppData/Local/Microsoft/Windows/WebCache/")
        webcache_file = webcache_dir.joinpath(iexplore.InternetExplorerPlugin.CACHE_FILENAME)

        webcache_dir = str(webcache_dir)[3:]  # drop C:/
        webcache_file = str(webcache_file)[3:]  # drop C:/

        fs_win.map_dir(webcache_dir, tmp_path)
        fs_win.map_file(webcache_file, tf.name)

        target_win.add_plugin(iexplore.InternetExplorerPlugin)

        records = list(target_win.iexplore.history())
        assert len(records) == 41

        records = list(target_win.browser.history())
        assert len(records) == 41

        records = list(target_win.iexplore.downloads())
        assert len(records) == 1
        assert records[0].path == "C:\\Users\\John\\Downloads\\archlinux-2023.02.01-x86_64.iso"
        assert records[0].url == "https://mirror.cj2.nl/archlinux/iso/2023.02.01/archlinux-2023.02.01-x86_64.iso"

        records = list(target_win.browser.downloads())
        assert len(records) == 1
        assert records[0].path == "C:\\Users\\John\\Downloads\\archlinux-2023.02.01-x86_64.iso"
        assert records[0].url == "https://mirror.cj2.nl/archlinux/iso/2023.02.01/archlinux-2023.02.01-x86_64.iso"


def test_firefox_plugin(target_win, fs_win, tmp_path, target_win_users):
    firefox_db = absolute_path("_data/plugins/apps/browser/firefox/places.sqlite")

    user = target_win_users.user_details.find(username="John")
    webcache_dir = user.home_path.joinpath("AppData/local/Mozilla/Firefox/Profiles/g1rbw8y7.default-release/")
    webcache_file = webcache_dir.joinpath("places.sqlite")

    webcache_dir = str(webcache_dir)[3:]  # drop C:/
    webcache_file = str(webcache_file)[3:]  # drop C:/

    fs_win.map_dir("Users\\John", tmp_path)
    fs_win.map_file(webcache_file, firefox_db)

    target_win.add_plugin(firefox.FirefoxPlugin)

    records = list(target_win.firefox.history())
    assert len(records) == 24

    records = list(target_win.browser.history())
    assert len(records) == 24

    records = list(target_win.firefox.downloads())
    assert len(records) == 3

    records = list(target_win.browser.downloads())
    assert len(records) == 3


def test_chrome_plugin(target_win, fs_win, tmp_path, target_win_users):
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

    records = list(target_win.chrome.downloads())
    assert len(records) == 1
    records = list(target_win.chrome.extensions())
    assert len(records) == 8
    records = list(target_win.chrome.history())
    assert len(records) == 5

    records = list(target_win.browser.downloads())
    assert len(records) == 1
    records = list(target_win.browser.extensions())
    assert len(records) == 8
    records = list(target_win.browser.history())
    assert len(records) == 5


def test_edge_plugin(target_win, fs_win, tmp_path, target_win_users):
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

    records = list(target_win.edge.downloads())
    assert len(records) == 2
    records = list(target_win.edge.extensions())
    assert len(records) == 39
    records = list(target_win.edge.history())
    assert len(records) == 45

    records = list(target_win.browser.downloads())
    assert len(records) == 2
    records = list(target_win.browser.extensions())
    assert len(records) == 39
    records = list(target_win.browser.history())
    assert len(records) == 45


def test_chromium_plugin(target_win, fs_win, tmp_path, target_win_users):
    chromium_db = absolute_path("_data/plugins/apps/browser/chromium/History.sqlite")
    chromium_prefs = absolute_path("_data/plugins/apps/browser/chromium/windows/Preferences")
    chromium_sec_prefs = absolute_path("_data/plugins/apps/browser/chromium/windows/Secure Preferences")

    user = target_win_users.user_details.find(username="John")
    webcache_dir = user.home_path.joinpath("AppData/Local/Chromium/User Data/Default")
    webcache_file = webcache_dir.joinpath("History")
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

    records = list(target_win.chromium.downloads())
    assert len(records) == 1
    records = list(target_win.chromium.extensions())
    assert len(records) == 4
    records = list(target_win.chromium.history())
    assert len(records) == 5

    records = list(target_win.browser.downloads())
    assert len(records) == 1
    records = list(target_win.browser.extensions())
    assert len(records) == 4
    records = list(target_win.browser.history())
    assert len(records) == 5
