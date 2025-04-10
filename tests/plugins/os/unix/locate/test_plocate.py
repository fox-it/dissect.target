from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.locate.plocate import PLocatePlugin, PLocateRecord
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_plocate(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file("/var/lib/plocate/plocate.db", absolute_path("_data/plugins/os/unix/locate/plocate.db"))
    target_unix.add_plugin(PLocatePlugin)

    records = list(target_unix.plocate.locate())

    assert len(records) == 3594
    assert isinstance(records[0], type(PLocateRecord()))

    assert records[0].path.as_posix() == "/.dockerenv"
    assert records[1].path.as_posix() == "/bin"

    # regression for issue #696 (https://github.com/fox-it/dissect.target/issues/696)
    # records[31] would be `/etc/cron.daily/etc/debconf.conf` without the fix
    assert records[31].path.as_posix() == "/etc/cron.daily"
    assert records[32].path.as_posix() == "/etc/debconf.conf"
