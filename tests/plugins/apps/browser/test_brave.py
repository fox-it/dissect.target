from typing import Iterator

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.browser import brave
from tests._utils import absolute_path


@pytest.fixture
def target_brave(target_win_users: Target, fs_win: VirtualFilesystem) -> Iterator[Target]:
    base_path_default = "Users\\John\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default"
    base_path_profile = "Users\\John\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1"
    files = [
        ("History", "_data/plugins/apps/browser/chrome/History"),
        ("Preferences", "_data/plugins/apps/browser/chrome/Preferences"),
        ("Secure Preferences", "_data/plugins/apps/browser/chrome/Secure Preferences"),
        ("Network\\Cookies", "_data/plugins/apps/browser/chromium/Cookies"),
        ("Login Data", "_data/plugins/apps/browser/chromium/Login Data"),
    ]

    for filename, test_path in files:
        fs_win.map_file("\\".join([base_path_default, filename]), absolute_path(test_path))
        fs_win.map_file("\\".join([base_path_profile, filename]), absolute_path(test_path))

    target_win_users.add_plugin(brave.BravePlugin)

    yield target_win_users


def test_brave_history(target_brave: Target) -> None:
    records = list(target_brave.brave.history())
    assert len(records) == 10


def test_brave_downloads(target_brave: Target) -> None:
    records = list(target_brave.brave.downloads())
    assert len(records) == 2


def test_brave_extensions(target_brave: Target) -> None:
    records = list(target_brave.brave.extensions())
    assert len(records) == 16


def test_brave_cookies(target_brave: Target) -> None:
    records = list(target_brave.brave.cookies())
    assert len(records) == 10
    assert all(record.host == ".tweakers.net" for record in records)


def test_windows_edge_passwords_plugin(target_brave: Target) -> None:
    records = list(target_brave.brave.passwords())

    assert len(records) == 4

    for record in records:
        assert record.browser == "brave"
        assert record.decrypted_username == "username"
        assert record.decrypted_password is None

    assert records[0].url == "https://example.com/"
    assert records[1].url == "https://example.org/"
