from typing import Iterator

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.browser import chromium
from tests._utils import absolute_path


@pytest.fixture
def target_chromium(target_win_users: Target, fs_win: VirtualFilesystem) -> Iterator[Target]:
    base_path = "Users\\John\\AppData\\Local\\Chromium\\User Data\\Default"
    files = [
        ("History", "_data/plugins/apps/browser/chromium/History.sqlite"),
        ("Cookies", "_data/plugins/apps/browser/chromium/Cookies.sqlite"),
        ("Preferences", "_data/plugins/apps/browser/chromium/windows/Preferences"),
        ("Secure Preferences", "_data/plugins/apps/browser/chromium/windows/Secure Preferences"),
    ]

    for filename, test_path in files:
        fs_win.map_file("\\".join([base_path, filename]), absolute_path(test_path))

    target_win_users.add_plugin(chromium.ChromiumPlugin)

    yield target_win_users


def test_chromium_history(target_chromium: Target) -> None:
    records = list(target_chromium.chromium.history())
    assert len(records) == 5


def test_chromium_downloads(target_chromium: Target) -> None:
    records = list(target_chromium.chromium.downloads())
    assert len(records) == 1


def test_chromium_cookies(target_chromium: Target) -> None:
    records = list(target_chromium.chromium.cookies())
    assert sorted([*map(lambda c: c.name, records)]) == [
        "pl",
        "ssa-did",
        "ssa-sid",
        "tbb",
        "twk-theme",
    ]


def test_chromium_extensions(target_chromium: Target) -> None:
    records = list(target_chromium.chromium.extensions())
    assert len(records) == 4
