from datetime import datetime, timezone

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.locate.mlocate import (
    MLocateDirectoryRecord,
    MLocateEntryRecord,
    MLocatePlugin,
)
from dissect.target.target import Target
from tests._utils import absolute_path


def test_mlocate(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file("/var/lib/mlocate/mlocate.db", absolute_path("_data/plugins/os/unix/locate/mlocate.db"))
    target_unix.add_plugin(MLocatePlugin)

    records = list(target_unix.mlocate.locate())
    assert len(records) == 3896

    root_directory = records[0]
    assert isinstance(root_directory, type(MLocateDirectoryRecord()))
    assert root_directory.path == "/"
    assert root_directory.ts == datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    entry = records[1]
    assert isinstance(entry, type(MLocateEntryRecord()))
    assert entry.path == "/.dockerenv"
    assert entry.type == "file"

    entry = records[2]
    assert isinstance(entry, type(MLocateEntryRecord()))
    assert entry.path == "/bin"
    assert entry.type == "file"  # symlink
