from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.locate.gnulocate import (
    GNULocatePlugin,
    GNULocateRecord,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_gnulocate(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file("/var/cache/locate/locatedb", absolute_path("_data/plugins/os/unix/locate/locatedb"))
    target_unix.add_plugin(GNULocatePlugin)

    records = list(target_unix.gnulocate.locate())

    assert len(records) == 3575
    assert isinstance(records[0], type(GNULocateRecord()))

    assert records[0].path.as_posix() == "/"
    assert records[1].path.as_posix() == "/.dockerenv"

    # test namespace plugin
    records = list(target_unix.locate.locate())

    assert len(records) == 3575
    assert isinstance(records[0], type(GNULocateRecord()))

    assert records[0].path.as_posix() == "/"
    assert records[1].path.as_posix() == "/.dockerenv"
