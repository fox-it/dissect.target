from typing import Iterator

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.browser import chrome
from tests._utils import absolute_path


@pytest.fixture
def target_chrome(target_win_users: Target, fs_win: VirtualFilesystem) -> Iterator[Target]:
    base_path = "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Default"
    files = [
        ("History", "_data/plugins/apps/browser/chrome/History.sqlite"),
        ("Preferences", "_data/plugins/apps/browser/chrome/windows/Preferences"),
        ("Secure Preferences", "_data/plugins/apps/browser/chrome/windows/Secure Preferences"),
    ]

    for filename, test_path in files:
        fs_win.map_file("\\".join([base_path, filename]), absolute_path(test_path))

    target_win_users.add_plugin(chrome.ChromePlugin)

    yield target_win_users


def test_chrome_history(target_chrome: Target) -> None:
    records = list(target_chrome.chrome.history())
    assert len(records) == 5


def test_chrome_downloads(target_chrome: Target) -> None:
    records = list(target_chrome.chrome.downloads())
    assert len(records) == 1


def test_chrome_extensions(target_chrome: Target) -> None:
    records = list(target_chrome.chrome.extensions())
    assert len(records) == 8
