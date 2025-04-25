from __future__ import annotations

import gzip
import tarfile
import textwrap
from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import patch
from zoneinfo import ZoneInfo

from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.plugins.os.unix._os import UnixPlugin
from dissect.target.plugins.os.unix.log.messages import MessagesPlugin, MessagesRecord
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem


def test_unix_log_messages_plugin(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/etc/timezone", BytesIO(b"Europe/Amsterdam"))

    data_file = absolute_path("_data/plugins/os/unix/log/messages/messages")
    fs_unix.map_file("var/log/messages", data_file)

    entry = fs_unix.get("var/log/messages")
    stat = entry.stat()
    stat.st_mtime = datetime(2022, 6, 1, tzinfo=timezone.utc).timestamp()

    with patch.object(entry, "stat", return_value=stat):
        target_unix_users.add_plugin(MessagesPlugin)

        results = list(target_unix_users.messages())
        assert len(results) == 2

        assert results[0].ts == datetime(2022, 1, 1, 13, 21, 34, tzinfo=ZoneInfo("Europe/Amsterdam"))
        assert results[0].message == "Stopped target Swap."
        assert results[0].pid is None
        assert results[0].source == "/var/log/messages"

        assert results[1].ts == datetime(2021, 12, 31, 3, 14, 15, tzinfo=ZoneInfo("Europe/Amsterdam"))
        assert results[1].message == "Starting Journal Service..."
        assert results[1].pid == 1
        assert results[1].source == "/var/log/messages"

    # assure syslog() behaves the same as messages()
    syslogs = list(target_unix_users.syslog())
    assert len(syslogs) == len(results)
    assert isinstance(syslogs[0], type(MessagesRecord()))


def test_unix_log_messages_compressed_timezone_year_rollover() -> None:
    target = Target()
    bio = BytesIO()

    with tarfile.open(mode="w:gz", fileobj=bio) as tf:
        # UTC-6 tar filesystem
        timezone_contents = "America/Chicago"
        timezone_file = BytesIO(textwrap.dedent(timezone_contents).encode())
        timezone_tar_info = tarfile.TarInfo("etc/timezone")
        timezone_tar_info.size = len(timezone_contents)
        tf.addfile(timezone_tar_info, timezone_file)

        # Create a tar file with correct mtime
        messages_log_contents = """\
        Dec 31 03:14:00 localhost systemd[1]: Starting Journal Service...
        \xfean  1 03:14:00 localhost systemd[1]: Starting Journal Service...
        Jan  1 13:37:00 localhost systemd: Stopped target Swap."""
        messages_log_file = BytesIO(textwrap.dedent(messages_log_contents).encode())
        messages_log_tar_info = tarfile.TarInfo("var/log/messages")
        messages_log_tar_info.size = len(textwrap.dedent(messages_log_contents))
        messages_log_tar_info.mtime = 1640995800  # (Sat 1 January 2022 00:10:00 UTC)
        tf.addfile(messages_log_tar_info, messages_log_file)

    fs = TarFilesystem(bio)
    target.filesystems.add(fs)
    target.fs.mount("/", fs)
    target._os_plugin = UnixPlugin
    target.apply()
    target.add_plugin(MessagesPlugin)

    results = list(target.messages())
    results.reverse()

    assert len(results) == 2
    assert isinstance(results[0], type(MessagesRecord()))
    assert isinstance(results[1], type(MessagesRecord()))
    assert results[0].ts == datetime(2020, 12, 31, 3, 14, 0, tzinfo=ZoneInfo("America/Chicago"))
    assert results[1].ts == datetime(2021, 1, 1, 13, 37, 0, tzinfo=ZoneInfo("America/Chicago"))


def test_unix_log_messages_malformed_log_year_rollover(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/etc/timezone", BytesIO(b"Europe/Amsterdam"))

    messages = BytesIO(
        b"Dec 31 03:14:00 localhost systemd[1]: Starting Journal Service...\r\n"
        b"\xefan  1 13:37:00 localhost systemd: Stopped target Swap.\r\n"
        b"Dec 31 03:14:00 localhost systemd[1]: Starting Journal Service...\r\n"
    )
    fs_unix.map_file_fh("var/log/messages", messages)

    entry = fs_unix.get("var/log/messages")
    stat = entry.stat()
    stat.st_mtime = datetime(2022, 6, 1, tzinfo=timezone.utc).timestamp()

    with patch.object(entry, "stat", return_value=stat):
        target_unix_users.add_plugin(MessagesPlugin)

        results = list(target_unix_users.messages())
        assert len(results) == 2

        assert results[0].ts
        assert results[0].service == "systemd"
        assert results[0].pid == 1
        assert results[0].message == "Starting Journal Service..."
        assert results[0].source == "/var/log/messages"


def test_unix_messages_cloud_init(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we correctly parse plaintext and compressed cloud-init log files."""

    messages = """
    2005-08-09 11:55:21,000 - foo.py[DEBUG]: This is a cloud-init message!
    2005-08-09 11:55:21,001 - util.py[DEBUG]: Cloud-init v. 1.2.3-4ubuntu5 running 'init-local' at Tue, 9 Aug 2005 11:55:21 +0000. Up 13.37 seconds.
    """  # noqa: E501
    msg_bytes = textwrap.dedent(messages).encode()

    fs_unix.map_file_fh("/etc/timezone", BytesIO(b"Europe/Amsterdam"))
    fs_unix.map_file_fh("/var/log/installer/cloud-init.log", BytesIO(msg_bytes))
    fs_unix.map_file_fh("/var/log/installer/cloud-init.log.1.gz", BytesIO(gzip.compress(msg_bytes)))
    target_unix.add_plugin(MessagesPlugin)

    results = sorted(target_unix.messages(), key=lambda r: r.source)
    assert len(results) == 4

    assert results[0].ts == datetime(2005, 8, 9, 11, 55, 21, 0, tzinfo=ZoneInfo("Europe/Amsterdam"))
    assert results[0].service == "foo.py"
    assert results[0].pid is None
    assert results[0].message == "This is a cloud-init message!"
    assert results[0].source == "/var/log/installer/cloud-init.log"

    assert results[-1].ts == datetime(2005, 8, 9, 11, 55, 21, 1_000, tzinfo=ZoneInfo("Europe/Amsterdam"))
    assert results[-1].service == "util.py"
    assert results[-1].pid is None
    assert (
        results[-1].message
        == "Cloud-init v. 1.2.3-4ubuntu5 running 'init-local' at Tue, 9 Aug 2005 11:55:21 +0000. Up 13.37 seconds."
    )
    assert results[-1].source == "/var/log/installer/cloud-init.log.1.gz"


def test_unix_messages_ts_iso_8601_format(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we correctly detect and parse ISO 8601 formatted syslog logs."""

    fs_unix.map_file_fh("/etc/hostname", BytesIO(b"hostname"))
    messages = """
    2024-12-31T13:37:00.123456+02:00 hostname systemd[1]: Started anacron.service - Run anacron jobs.
    2024-12-31T13:37:00.123456+02:00 hostname anacron[1337]: Anacron 2.3 started on 2024-12-31
    2024-12-31T13:37:00.123456+02:00 hostname anacron[1337]: Normal exit (0 jobs run)
    2024-12-31T13:37:00.123456+02:00 hostname systemd[1]: anacron.service: Deactivated successfully.
    """
    fs_unix.map_file_fh("/var/log/syslog.1", BytesIO(gzip.compress(textwrap.dedent(messages).encode())))

    target_unix.add_plugin(UnixPlugin)
    target_unix.add_plugin(MessagesPlugin)
    results = sorted(target_unix.syslog(), key=lambda r: r.ts)

    assert len(results) == 4

    assert results[0].hostname == "hostname"
    assert results[0].service == "systemd"
    assert results[0].pid == 1
    assert results[0].ts == datetime(2024, 12, 31, 11, 37, 0, 123456, tzinfo=timezone.utc)
    assert results[0].message == "Started anacron.service - Run anacron jobs."
    assert results[0].source == "/var/log/syslog.1"


def test_linux_messages_kernel_logs(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can parse kernel ring buffer messages."""

    messages = """
    Dec 31 13:37:01 hostname kernel: [1337.1337] some example message
    Jan  1 13:37:02 kernel: [    0.000000] x86/fpu: Supporting feature 0x1337: 'message'
    Jan  2 13:37:03 kernel: [    0.000000] x86/fpu: state[1337]:  1337, size[1337]:   1337
    Jan  3 13:37:04 kernel:
    """

    fs_unix.map_file_fh("/var/log/installer/syslog.1", BytesIO(gzip.compress(textwrap.dedent(messages).encode())))
    target_unix.add_plugin(UnixPlugin)
    target_unix.add_plugin(MessagesPlugin)

    results = sorted(target_unix.syslog(), key=lambda r: r.ts)
    assert len(results) == 4

    assert results[0].service == "kernel"
    assert results[0].message == "[1337.1337] some example message"

    assert results[1].service == "kernel"
    assert results[1].message == "[    0.000000] x86/fpu: Supporting feature 0x1337: 'message'"

    assert results[2].service == "kernel"
    assert results[2].message == "[    0.000000] x86/fpu: state[1337]:  1337, size[1337]:   1337"

    assert results[3].service == "kernel"
    assert results[3].message is None
