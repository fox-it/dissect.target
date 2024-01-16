from typing import Iterator

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.browser import edge
from tests._utils import absolute_path


@pytest.fixture
def target_edge(target_win_users: Target, fs_win: VirtualFilesystem) -> Iterator[Target]:
    base_path = "Users\\John\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default"
    files = [
        ("History", "_data/plugins/apps/browser/edge/History.sqlite"),
        ("Preferences", "_data/plugins/apps/browser/edge/windows/Preferences"),
        ("Secure Preferences", "_data/plugins/apps/browser/edge/windows/Secure Preferences"),
    ]

    for filename, test_path in files:
        fs_win.map_file("\\".join([base_path, filename]), absolute_path(test_path))

    target_win_users.add_plugin(edge.EdgePlugin)

    yield target_win_users


def test_edge_history(target_edge: Target) -> None:
    records = list(target_edge.edge.history())
    assert len(records) == 45


def test_edge_downloads(target_edge: Target) -> None:
    records = list(target_edge.edge.downloads())
    assert len(records) == 2


def test_edge_extensions(target_edge: Target) -> None:
    records = list(target_edge.edge.extensions())
    assert len(records) == 39
