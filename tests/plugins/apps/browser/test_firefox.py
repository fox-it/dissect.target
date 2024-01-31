from typing import Iterator

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.browser import firefox
from tests._utils import absolute_path


@pytest.fixture
def target_firefox(target_win_users: Target, fs_win: VirtualFilesystem) -> Iterator[Target]:
    base_path = "Users\\John\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\g1rbw8y7.default-release"
    files = [
        ("places.sqlite", "_data/plugins/apps/browser/firefox/places.sqlite"),
        ("cookies.sqlite", "_data/plugins/apps/browser/firefox/cookies.sqlite"),
    ]

    for filename, test_path in files:
        fs_win.map_file("\\".join([base_path, filename]), absolute_path(test_path))

    target_win_users.add_plugin(firefox.FirefoxPlugin)

    yield target_win_users


def test_firefox_history(target_firefox: Target) -> None:
    records = list(target_firefox.firefox.history())
    assert len(records) == 24


def test_firefox_downloads(target_firefox: Target) -> None:
    records = list(target_firefox.firefox.downloads())
    assert len(records) == 3


def test_firefox_cookies(target_firefox: Target) -> None:
    records = list(target_firefox.firefox.cookies())
    assert sorted([*map(lambda c: c.name, records)]) == [
        "_lr_env_src_ats",
        "_lr_retry_request",
        "_uc_referrer",
        "_uc_referrer",
    ]
