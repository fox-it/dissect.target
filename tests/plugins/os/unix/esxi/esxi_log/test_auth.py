from __future__ import annotations

from typing import TYPE_CHECKING

from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.os.unix.esxi.esxi_log.auth import EsxiAuthPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_esxi_6_log_auth(target_esxi: Target, fs_esxi: VirtualFilesystem) -> None:
    """Test with log from an ESXi6"""
    data_file = absolute_path("_data/plugins/os/unix/esxi/log/esxi6/auth.log.gz")
    fs_esxi.map_file("/var/run/log/auth.log.gz", data_file)

    target_esxi.add_plugin(EsxiAuthPlugin)

    results = list(target_esxi.auth())
    assert len(results) == 20

    assert results[0].ts == dt("2025-08-22T07:41:20Z")
    assert results[0].application == "sshd"
    assert results[0].log_level is None
    assert results[0].pid == 2099481
    assert results[0].message == "/etc/ssh/sshd_config line 24: Unsupported option PrintLastLog"

    assert results[12].ts == dt("2025-08-22T07:42:12Z")
    assert results[12].application == "sshd"
    assert results[12].log_level is None
    assert results[12].pid == 2099486
    assert results[12].message == "Accepted keyboard-interactive/pam for root from 192.168.56.1 port 46932 ssh2"
    assert results[12].source == "/var/run/log/auth.log.gz"


def test_esxi_7_log_auth(target_esxi: Target, fs_esxi: VirtualFilesystem) -> None:
    """Test with log from an ESXi7"""
    data_file = absolute_path("_data/plugins/os/unix/esxi/log/esxi7/auth.log.gz")
    fs_esxi.map_file("/var/run/log/auth.log.gz", data_file)

    target_esxi.add_plugin(EsxiAuthPlugin)

    results = list(target_esxi.auth())
    assert len(results) == 33

    assert results[0].ts == dt("2024-12-06T10:58:46.714Z")
    assert results[0].application == "sshd"
    assert results[0].log_level is None
    assert results[0].pid == 2102622
    assert results[0].message == "FIPS mode initialized"
    assert results[0].source == "/var/run/log/auth.log.gz"

    assert results[4].ts == dt("2024-12-06T10:58:46.944Z")
    assert results[4].application == "sshd"
    assert results[4].log_level is None
    assert results[4].pid == 2102622
    assert results[4].message == (
        "User 'root' running command '/bin/sh -c '( umask 77 && mkdir -p \"` echo /var/core "
        '`"&& mkdir "` echo /var/core/ansible-tmp-1733482726.6630323-32096-231798679827098 `" && '
        "echo ansible-tmp-1733482726.6630323-32096-231798679827098=\"'"
    )
    assert results[4].source == "/var/run/log/auth.log.gz"


def test_esxi_9_log_auth(target_esxi: Target, fs_esxi: VirtualFilesystem) -> None:
    """
    Test with log from an ESXi9.
    In ESXi8+, logs seems to be nearly empty/useless
    """
    data_file = absolute_path("_data/plugins/os/unix/esxi/log/esxi9/auth.log.gz")
    fs_esxi.map_file("/var/run/log/auth.log.gz", data_file)

    target_esxi.add_plugin(EsxiAuthPlugin)

    results = list(target_esxi.auth())
    assert len(results) == 8

    assert results[0].ts == dt("2025-10-29T09:23:16.522Z")
    assert results[0].application == "sshd"
    assert results[0].log_level == "In(38)"
    assert results[0].pid == 132774
    assert results[0].message == "/etc/ssh/sshd_config line 14: Deprecated option fipsmode"
    assert results[0].source == "/var/run/log/auth.log.gz"
