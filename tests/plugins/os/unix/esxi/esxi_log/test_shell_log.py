from __future__ import annotations

from typing import TYPE_CHECKING

from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.os.unix.esxi.esxi_log.shell_log import ShellLogPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_esxi_6_log_shell(target_esxi: Target, fs_esxi: VirtualFilesystem) -> None:
    """Test with log from an ESXi6"""
    data_file = absolute_path("_data/plugins/os/unix/esxi/log/esxi6/shell.log.gz")
    fs_esxi.map_file("/var/run/log/shell.log.gz", data_file)

    target_esxi.add_plugin(ShellLogPlugin)

    results = list(target_esxi.shell_log())
    assert len(results) == 32

    assert results[0].ts == dt("2025-08-22T07:35:29Z")
    assert results[0].application is None
    assert results[0].log_level is None
    assert results[0].pid is None
    assert results[0].user is None
    assert results[0].message == "ESXShell: ESXi Shell unavailable"

    assert results[13].ts == dt("2025-08-22T07:43:46Z")
    assert results[13].application == "shell"
    assert results[13].log_level is None
    assert results[13].pid == 2099491
    assert results[13].message == "./uac --profile full -f zip ."
    assert results[13].user == "root"
    assert results[13].source == "/var/run/log/shell.log.gz"


def test_esxi_7_log_shell(target_esxi: Target, fs_esxi: VirtualFilesystem) -> None:
    """Test with log from an ESXi6"""
    data_file = absolute_path("_data/plugins/os/unix/esxi/log/esxi7/shell.log.gz")
    fs_esxi.map_file("/var/run/log/shell.log.gz", data_file)

    target_esxi.add_plugin(ShellLogPlugin)

    results = list(target_esxi.shell_log())
    assert len(results) == 7

    assert results[0].ts == dt("2024-12-06T10:32:18.779Z")
    assert results[0].application == "ESXShell"
    assert results[0].log_level is None
    assert results[0].pid == 2101297
    assert results[0].user is None
    assert results[0].message == "ESXi Shell unavailable"

    assert results[6].ts == dt("2024-12-06T15:18:56.247Z")
    assert results[6].application == "shell"
    assert results[6].log_level is None
    assert results[6].pid == 88029001
    assert results[6].message == "du -sh *"
    assert results[6].user == "anotheruser"


def test_esxi_8_log_shell(target_esxi: Target, fs_esxi: VirtualFilesystem) -> None:
    """Test with log from an ESXi6"""
    data_file = absolute_path("_data/plugins/os/unix/esxi/log/esxi8/shell.log.gz")
    fs_esxi.map_file("/var/run/log/shell.log.gz", data_file)

    target_esxi.add_plugin(ShellLogPlugin)

    results = list(target_esxi.shell_log())
    assert len(results) == 109

    assert results[0].ts == dt("2025-11-03T13:12:41.357Z")
    assert results[0].application == "ESXShell"
    assert results[0].log_level == "No(13)"
    assert results[0].pid == 132663
    assert results[0].user is None
    assert results[0].message == "ESXi Shell unavailable"

    assert results[13].ts == dt("2025-11-03T13:20:15.420Z")
    assert results[13].application == "shell"
    assert results[13].log_level == "In(14)"
    assert results[13].pid == 133026
    assert results[13].message == "esxcli system ssh client config list"
    assert results[13].user == "root"

    # Test long line, even if no usage of esxi new line delimiter has been identified in ESXi shell logs
    assert results[13].ts == dt("2025-11-03T13:20:15.420Z")
    assert results[13].application == "shell"
    assert results[13].log_level == "In(14)"
    assert results[13].pid == 133026
    assert results[13].message == "esxcli system ssh client config list"
    assert results[13].user == "root"

    assert results[101].ts == dt("2025-11-03T15:45:32.864Z")
    assert results[101].application == "shell"
    assert results[101].log_level == "In(14)"
    assert results[101].pid == 132941
    assert results[101].message == (
        'echo "this is a very very very very very very very very very very very very very very very very very very '
        'very very long command that is over 80 char, maybe more" | wc l'
    )
    assert results[101].user == "root"


def test_esxi_9_log_shell(target_esxi: Target, fs_esxi: VirtualFilesystem) -> None:
    """Test with log from an ESXi6"""
    data_file = absolute_path("_data/plugins/os/unix/esxi/log/esxi9/shell.log.gz")
    fs_esxi.map_file("/var/run/log/shell.log.gz", data_file)

    target_esxi.add_plugin(ShellLogPlugin)

    results = list(target_esxi.shell_log())
    assert len(results) == 34

    assert results[0].ts == dt("2025-10-28T16:02:09.689Z")
    assert results[0].application == "ESXShell"
    assert results[0].log_level == "No(13)"
    assert results[0].pid == 132660
    assert results[0].user is None
    assert results[0].message == "ESXi Shell unavailable"

    assert results[24].ts == dt("2025-11-03T12:48:57.082Z")
    assert results[24].application == "shell"
    assert results[24].log_level == "In(14)"
    assert results[24].pid == 132899
    assert results[24].message == "esxcli network ip route ipv4 list"
    assert results[24].user == "root"
