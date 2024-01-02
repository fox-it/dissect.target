from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.browser import firefox
from tests._utils import absolute_path


def test_firefox_history(
    target_win: Target, fs_win: VirtualFilesystem, tmp_path: str, target_win_users: Target
) -> None:
    __setup(target_win, fs_win, tmp_path, target_win_users, "places.sqlite")
    records = list(target_win.firefox.history())
    assert len(records) == 24


def test_firefox_downloads(
    target_win: Target, fs_win: VirtualFilesystem, tmp_path: str, target_win_users: Target
) -> None:
    __setup(target_win, fs_win, tmp_path, target_win_users, "places.sqlite")
    records = list(target_win.firefox.downloads())
    assert len(records) == 3


def test_firefox_cookies(
    target_win: Target, fs_win: VirtualFilesystem, tmp_path: str, target_win_users: Target
) -> None:
    __setup(target_win, fs_win, tmp_path, target_win_users, "cookies.sqlite")
    records = list(target_win.firefox.cookies())
    record_names = sorted([*map(lambda c: c.name, records)])
    assert record_names == ["_lr_env_src_ats", "_lr_retry_request", "_uc_referrer", "_uc_referrer"]


def __setup(target_win: Target, fs_win: VirtualFilesystem, tmp_path: str, target_win_users: Target, db: str) -> None:
    firefox_db = absolute_path(f"_data/plugins/apps/browser/firefox/{db}")

    user = target_win_users.user_details.find(username="John")
    webcache_dir = user.home_path.joinpath("AppData/local/Mozilla/Firefox/Profiles/g1rbw8y7.default-release/")
    webcache_file = webcache_dir.joinpath(db)

    webcache_dir = str(webcache_dir)[3:]  # drop C:/
    webcache_file = str(webcache_file)[3:]  # drop C:/

    fs_win.map_dir("Users\\John", tmp_path)
    fs_win.map_file(webcache_file, firefox_db)

    target_win.add_plugin(firefox.FirefoxPlugin)
