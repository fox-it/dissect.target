from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.apps.browser.safari import SafariPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_safari_mac(target_macos_users: Target, fs_macos: VirtualFilesystem) -> Target:
    fs_macos.map_dir(
        "/Users/dissect/Library/Safari/",
        absolute_path("_data/plugins/apps/browser/safari/generic/"),
    )
    target_macos_users.add_plugin(SafariPlugin)
    return target_macos_users


def test_safari_history(target_safari_mac: Target) -> None:
    records = list(target_safari_mac.safari.history())

    assert len(records) == 5
    assert {"safari"} == {r.browser for r in records}

    # First visit: direct navigation to example.com
    r = records[0]
    assert r.ts == dt("2024-01-01T00:00:00+00:00")
    assert r.url == "https://example.com/"
    assert r.title == "Example Domain"
    assert r.host == "example"
    assert r.visit_count == 3
    assert r.hidden == False
    assert r.from_visit is None
    assert r.from_url is None

    # Second visit: redirect from visit 1
    r = records[1]
    assert r.ts == dt("2024-01-01T00:01:00+00:00")
    assert r.url == "https://example.com/page"
    assert r.title == "Example Page"
    assert r.from_visit == 1
    assert r.from_url == "https://example.com/"

    # Fifth visit: synthesized (hidden)
    r = records[4]
    assert r.hidden == True
    assert r.title is None
