from datetime import datetime, timezone

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.log.atop import AtopPlugin
from dissect.target.target import Target
from tests._utils import absolute_path


def test_atop_plugin(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/os/unix/log/atop/atop")
    fs_unix.map_file("var/log/atop/atop_20221111", data_file)

    target_unix.add_plugin(AtopPlugin)

    results = list(target_unix.atop())
    assert len(results) == 2219
    assert results[0].ts == datetime(2022, 11, 11, 19, 50, 44, tzinfo=timezone.utc)
    assert results[0].process == "systemd"
    assert results[0].cmdline == "/sbin/init"
    assert results[0].tgid == 1
    assert results[0].pid == 1
    assert results[0].ppid == 0
    assert results[0].ruid == 0
    assert results[0].euid == 0
    assert results[0].suid == 0
    assert results[0].fsuid == 0
    assert results[0].rgid == 0
    assert results[0].egid == 0
    assert results[0].sgid == 0
    assert results[0].fsgid == 0
    assert results[0].nthr == 1
    assert bool(results[0].isproc) is True
    assert results[0].state == "S"
    assert results[0].excode == -2147483648
    assert results[0].elaps == 0
    assert results[0].nthrslpi == 1
    assert results[0].nthrslpu == 0
    assert results[0].nthrrun == 0
    assert results[0].ctid == 0
    assert results[0].vpid == 0
    assert bool(results[0].wasinactive) is False
    assert results[0].container == ""
    assert str(results[0].filepath) == "/var/log/atop/atop_20221111"
