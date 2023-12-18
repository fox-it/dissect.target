from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.linux.proc import ProcPlugin
from dissect.target.target import Target


def test_netstat(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem):
    target_linux_users.add_plugin(ProcPlugin)
    results = list(target_linux_users.netstat())[1:]  # Slice to skip over the header row
    assert len(results) == 18
