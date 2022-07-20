import tempfile
import gzip

from dissect.target.plugins.browsers import iexplore, firefox, chrome

from ._utils import absolute_path


def test_iexplore_plugin(target_win, fs_win, tmpdir_name, target_win_users):

    cache_archive = absolute_path("data/WebCacheV01.dat.gz")

    with tempfile.NamedTemporaryFile(dir=tmpdir_name) as tf:

        with gzip.GzipFile(cache_archive, "rb") as f:
            tf.write(f.read())
        tf.flush()

        user = target_win_users.user_details.find(username="John")
        webcache_dir = user.home_path.joinpath("AppData/Local/Microsoft/Windows/WebCache/")
        webcache_file = webcache_dir.joinpath(iexplore.InternetExplorerPlugin.CACHE_FILENAME)

        webcache_dir = str(webcache_dir)[3:]  # drop C:/
        webcache_file = str(webcache_file)[3:]  # drop C:/

        fs_win.map_dir("Users\\John", tmpdir_name)
        fs_win.map_file(webcache_file, tf.name)

        target_win.add_plugin(iexplore.InternetExplorerPlugin)

        records = list(target_win.iexplore.history())
        assert len(records) == 33

        records = list(target_win.browser.history())
        assert len(records) == 33


def test_firefox_plugin(target_win, fs_win, tmpdir_name, target_win_users):

    firefox_db = absolute_path("data/firefox-places.sqlite")

    user = target_win_users.user_details.find(username="John")
    webcache_dir = user.home_path.joinpath("AppData/local/Mozilla/Firefox/Profiles/g1rbw8y7.default-release/")
    webcache_file = webcache_dir.joinpath("places.sqlite")

    webcache_dir = str(webcache_dir)[3:]  # drop C:/
    webcache_file = str(webcache_file)[3:]  # drop C:/

    fs_win.map_dir("Users\\John", tmpdir_name)
    fs_win.map_file(webcache_file, firefox_db)

    target_win.add_plugin(firefox.FirefoxPlugin)

    records = list(target_win.firefox.history())
    assert len(records) == 29

    records = list(target_win.browser.history())
    assert len(records) == 29


def test_chrome_plugin(target_win, fs_win, tmpdir_name, target_win_users):

    firefox_db = absolute_path("data/chrome-history.sqlite")

    user = target_win_users.user_details.find(username="John")
    webcache_dir = user.home_path.joinpath("AppData/Local/Google/Chrome/continuousUpdates/User Data/Default")
    webcache_file = webcache_dir.joinpath("History")

    webcache_dir = str(webcache_dir)[3:]  # drop C:/
    webcache_file = str(webcache_file)[3:]  # drop C:/

    fs_win.map_dir("Users\\John", tmpdir_name)
    fs_win.map_file(webcache_file, firefox_db)

    target_win.add_plugin(chrome.ChromePlugin)

    records = list(target_win.chrome.history())
    assert len(records) == 7

    records = list(target_win.browser.history())
    assert len(records) == 7
