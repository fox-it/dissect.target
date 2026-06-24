from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.linux.redhat.epmm._os import IvantiEpmmPlugin
from tests._utils import absolute_path
from tests.conftest import make_os_target

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


@pytest.fixture
def fs_epmm() -> VirtualFilesystem:
    fs = VirtualFilesystem()
    fs.map_file_fh(
        "etc/os-release",
        BytesIO(b"Oracle Linux Server 13.37"),
    )
    fs.map_file_fh(
        "mi/release",
        BytesIO(b"Example Standalone 1.2.3 Build 4 (Branch example-1.2.3-example-release)"),
    )
    fs.map_file(
        "mi/config-system/startup_config/systemconfig.xml",
        absolute_path("_data/plugins/os/unix/linux/redhat/epmm/systemconfig.xml"),
    )
    fs.map_file(
        "mi/config-system/startup_config/identityconfig.xml",
        absolute_path("_data/plugins/os/unix/linux/redhat/epmm/identityconfig.xml"),
    )
    return fs


@pytest.fixture
def target_epmm(tmp_path: Path, fs_epmm: VirtualFilesystem) -> Target:
    return make_os_target(tmp_path, IvantiEpmmPlugin, root_fs=fs_epmm)


def test_ivanti_epmm(target_epmm: Target, fs_epmm: VirtualFilesystem) -> None:
    """Test if we can detect and parse system configuration of Ivanti EPMM (Mobile Iron Core)."""
    assert target_epmm.os == "linux"
    assert (
        target_epmm.version
        == "Ivanti EPMM Example Standalone 1.2.3 Build 4 (Branch example-1.2.3-example-release) (Oracle Linux Server 13.37)"  # noqa: E501
    )

    assert target_epmm.hostname == "epmm.example.com"
    assert target_epmm.domain == "example.com"
    assert target_epmm.ips == ["1.2.3.4"]

    user = next(target_epmm.users())
    assert user.name == "username"
    assert user.password == "$6$...$..."
    assert user.gecos == "First Last,,,,username@example.com"
    assert user.groups == ["DEFAULT"]
    assert user.roles == ["ROLE_EXAMPLE_1", "ROLE_EXAMPLE_2"]
    assert user.source == "/mi/config-system/startup_config/identityconfig.xml"
