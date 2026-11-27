from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.apps.browser.ladybird import LadybirdPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_ladybird(target_unix_users: Target, fs_unix: VirtualFilesystem) -> Target:
    fs_unix.map_dir(
        "/home/user/.config/Ladybird/Profiles/default", absolute_path("_data/plugins/apps/browser/ladybird/config")
    )
    fs_unix.map_dir(
        "/home/user/.local/share/Ladybird/Profiles/default", absolute_path("_data/plugins/apps/browser/ladybird/data")
    )
    return target_unix_users


def test_ladybird_cookies(target_ladybird: Target) -> None:
    """Test if we can detect and parse Ladybird browser cookies."""
    target_ladybird.add_plugin(LadybirdPlugin)
    records = list(target_ladybird.ladybird.cookies())
    assert len(records) == 18

    assert records[0].ts_created == datetime(2026, 11, 24, 16, 36, 41, 340000, tzinfo=timezone.utc)
    assert records[0].ts_last_accessed == datetime(2026, 11, 24, 16, 36, 41, 340000, tzinfo=timezone.utc)
    assert records[0].browser == "ladybird"
    assert records[0].name == "WMF-Last-Access"
    assert records[0].value == "24-Nov-2026"
    assert records[0].host == "wikipedia.org"
    assert records[0].path == "/"
    assert records[0].expiry == 1798286400
    assert records[0].is_secure
    assert records[0].is_http_only
    assert records[0].same_site
    assert records[0].source == "/home/user/.local/share/Ladybird/Profiles/default/Ladybird.db"
    assert records[0].username == "user"


def test_ladybird_localstorage(target_ladybird: Target) -> None:
    """Test if we can detect and aprse Ladybird browser LocalStorage."""
    target_ladybird.add_plugin(LadybirdPlugin)
    records = list(target_ladybird.ladybird.localstorage())
    assert len(records) == 10

    assert not records[0].ts_created
    assert records[0].ts_last_accessed == datetime(2026, 11, 24, 16, 36, 41, 904000, tzinfo=timezone.utc)
    assert not records[0].ts_last_modified
    assert records[0].browser == "ladybird"
    assert records[0].host == "https://www.wikipedia.org"
    assert records[0].key == "portal_test_group_expires"
    assert records[0].value == "1795539101903"
    assert records[0].source == "/home/user/.local/share/Ladybird/Profiles/default/Ladybird.db"
    assert records[0].username == "user"


def test_ladybird_history(target_ladybird: Target) -> None:
    """Test if we can detect and aprse Ladybird browser history."""
    target_ladybird.add_plugin(LadybirdPlugin)
    records = list(target_ladybird.ladybird.history())
    assert len(records) == 4

    assert records[0].ts == datetime(2026, 11, 24, 16, 36, 41, 546000, tzinfo=timezone.utc)
    assert records[0].browser == "ladybird"
    assert records[0].url == "https://www.wikipedia.org/"
    assert records[0].title == "Wikipedia"
    assert records[0].host == "www.wikipedia.org"
    assert records[0].visit_count == 1
    assert records[0].source == "/home/user/.local/share/Ladybird/Profiles/default/History.db"
    assert records[0].username == "user"


def test_ladybird_bookmarks(target_ladybird: Target) -> None:
    """Test if we can detect and aprse Ladybird browser bookmarks."""
    target_ladybird.add_plugin(LadybirdPlugin)
    records = list(target_ladybird.ladybird.bookmarks())
    assert len(records) == 3

    assert records[0].ts_added == datetime(2026, 11, 24, 16, 36, 14, 46000, tzinfo=timezone.utc)
    assert records[0].ts_modified == datetime(2026, 11, 24, 16, 36, 14, 46000, tzinfo=timezone.utc)
    assert records[0].url == "https://ladybird.org/"
    assert records[0].title == "Ladybird"
    assert records[0].id == "7b343024-6fb3-4a61-8098-6cb8981120d7"
    assert records[0].source == "/home/user/.config/Ladybird/Profiles/default/Bookmarks.json"
    assert records[0].username == "user"
