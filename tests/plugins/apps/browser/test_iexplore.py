import gzip
import tempfile

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.browser import iexplore
from tests._utils import absolute_path


def test_iexplore_history(
    target_win: Target, fs_win: VirtualFilesystem, tmp_path: str, target_win_users: Target
) -> None:
    __setup(target_win, fs_win, tmp_path, target_win_users)

    records = list(target_win.iexplore.history())
    assert len(records) == 41

    records = list(target_win.browser.history())
    assert len(records) == 41


def test_iexplore_downloads(
    target_win: Target, fs_win: VirtualFilesystem, tmp_path: str, target_win_users: Target
) -> None:
    __setup(target_win, fs_win, tmp_path, target_win_users)

    records = list(target_win.iexplore.downloads())
    assert len(records) == 1
    assert records[0].path.as_posix() == "C:\\Users\\John\\Downloads\\archlinux-2023.02.01-x86_64.iso"
    assert records[0].url == "https://mirror.cj2.nl/archlinux/iso/2023.02.01/archlinux-2023.02.01-x86_64.iso"


def __setup(target_win: Target, fs_win: VirtualFilesystem, tmp_path: str, target_win_users: Target) -> None:
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
