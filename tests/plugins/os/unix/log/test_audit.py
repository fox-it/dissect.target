from __future__ import annotations

import textwrap
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.util.ts import from_unix

from dissect.target.plugins.os.unix.log.audit import AuditPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_audit_plugin(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/os/unix/log/audit/audit.log")
    fs_unix.map_file("var/log/audit/audit.log", data_file)

    target_unix.add_plugin(AuditPlugin)
    results = list(target_unix.audit())

    assert len(results) == 4

    result = results[0]
    assert result.audit_type == "SYSCALL"
    assert result.ts == from_unix(1364481363.243)
    assert result.audit_id == 24287
    assert (
        result.message
        == 'arch=c000003e syscall=2 success=no exit=-13 a0=7fffd19c5592 a1=0 a2=7fffd19c4b50 a3=a items=1 ppid=2686 pid=3538 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="cat" exe="/bin/cat" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="sshd_config"'  # noqa E501
    )

    result = results[1]
    assert result.audit_type == "CWD"
    assert result.ts == from_unix(1364481363.243)
    assert result.audit_id == 24287
    assert result.message == 'cwd="/home/shadowman"'


def test_audit_plugin_config(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    config = """
    log_file = /foo/bar/audit/audit.log
    # log_file=/tmp/disabled/audit/audit.log
    """
    fs_unix.map_file_fh("etc/audit/auditd.conf", BytesIO(textwrap.dedent(config).encode()))
    fs_unix.map_file_fh("tmp/disabled/audit/audit.log", BytesIO(b"Foo"))
    fs_unix.map_file_fh("foo/bar/audit/audit.log", BytesIO(b"Foo"))

    log_paths = AuditPlugin(target_unix).get_log_paths()
    assert len(log_paths) == 2
    assert str(log_paths[0]) == "/foo/bar/audit/audit.log"
    assert str(log_paths[1]) == "/tmp/disabled/audit/audit.log"
