from typing import Iterator

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.browser import brave
from tests._utils import absolute_path


@pytest.fixture
def target_brave(target_win_users: Target, fs_win: VirtualFilesystem) -> Iterator[Target]:
    base_path = "Users\\John\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default"
    files = [
        ("History", "_data/plugins/apps/browser/chrome/History.sqlite"),
        ("Preferences", "_data/plugins/apps/browser/chrome/windows/Preferences"),
        ("Secure Preferences", "_data/plugins/apps/browser/chrome/windows/Secure Preferences"),
        ("Network\\Cookies", "_data/plugins/apps/browser/chromium/Cookies.sqlite"),
    ]

    for filename, test_path in files:
        fs_win.map_file("\\".join([base_path, filename]), absolute_path(test_path))

    target_win_users.add_plugin(brave.BravePlugin)

    yield target_win_users


def test_brave_history(target_brave: Target) -> None:
    records = list(target_brave.brave.history())
    assert len(records) == 5


def test_brave_downloads(target_brave: Target) -> None:
    records = list(target_brave.brave.downloads())
    assert len(records) == 1


def test_brave_extensions(target_brave: Target) -> None:
    records = list(target_brave.brave.extensions())
    assert len(records) == 8


def test_brave_cookies(target_brave: Target) -> None:
    records = list(target_brave.brave.cookies())
    assert len(records) == 5
    assert all(record.host == ".tweakers.net" for record in records)
