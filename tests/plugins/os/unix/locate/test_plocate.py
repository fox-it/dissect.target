from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.locate.plocate import PLocatePlugin, PLocateRecord
from dissect.target.target import Target
from tests._utils import absolute_path


def test_plocate(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file("/var/lib/plocate/plocate.db", absolute_path("_data/plugins/os/unix/locate/plocate.db"))
    target_unix.add_plugin(PLocatePlugin)

    records = list(target_unix.plocate.locate())

    assert len(records) == 3481
    assert isinstance(records[0], type(PLocateRecord()))

    assert records[0].path.as_posix() == "/.dockerenv"
    assert records[1].path.as_posix() == "/bin"
