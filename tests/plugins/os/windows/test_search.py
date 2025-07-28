from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows.search import SearchIndexPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_windows_search_esedb(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Test Windows Search EseDB parsing.

    Resources:
        - https://github.com/strozfriedberg/sidr/tree/main/tests/testdata
    """

    fs_win.map_file(
        "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb",
        str(absolute_path("_data/plugins/os/windows/search/Windows.edb")),
    )

    target_win.add_plugin(SearchIndexPlugin)

    records = list(target_win.search())

    assert len(records) == 1183


def test_windows_search_sqlite(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Test Windows 11 Search SQLite3 parsing.

    Resources:
        - https://github.com/strozfriedberg/sidr/tree/main/tests/testdata
    """

    fs_win.map_file(
        "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.db",
        str(absolute_path("_data/plugins/os/windows/search/Windows.db")),
    )

    target_win.add_plugin(SearchIndexPlugin)

    records = list(target_win.search())

    assert len(records) == 839
