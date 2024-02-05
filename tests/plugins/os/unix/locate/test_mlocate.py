from datetime import datetime, timezone

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.locate.mlocate import MLocatePlugin, MLocateRecord
from dissect.target.target import Target
from tests._utils import absolute_path


def test_mlocate(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file("/var/lib/mlocate/mlocate.db", absolute_path("_data/plugins/os/unix/locate/mlocate.db"))
    target_unix.add_plugin(MLocatePlugin)

    records = list(target_unix.mlocate.locate())
    assert len(records) == 3317

    root_directory = records[0]
    assert isinstance(root_directory, type(MLocateRecord()))
    assert root_directory.parent == "/"
    assert root_directory.path == "/.dockerenv"
    assert root_directory.ts == datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    entry = records[1]
    assert isinstance(entry, type(MLocateRecord()))
    assert entry.parent == "/"
    assert entry.path == "/bin"
    assert entry.type == "file"  # symlink

    entry = records[2]
    assert isinstance(entry, type(MLocateRecord()))
    assert entry.parent == "/"
    assert entry.path == "/boot"
    assert entry.type == "directory"

    entry = records[1337]
    assert isinstance(entry, type(MLocateRecord()))
    assert entry.parent == "/usr/lib/x86_64-linux-gnu/perl-base/unicore/lib/Bc"
    assert entry.path == "/usr/lib/x86_64-linux-gnu/perl-base/unicore/lib/Bc/WS.pl"
    assert entry.type == "file"
    assert entry.ts == datetime(2024, 1, 15, 12, 16, 7, tzinfo=timezone.utc)
