from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING, Callable
from unittest.mock import MagicMock, patch

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.vmx import VmxLoader
from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@contextlib.contextmanager
def _mock_vmx_and_container_open(disks: list[str]) -> Iterator[MagicMock]:
    with (
        patch("dissect.hypervisor.descriptor.vmx.VMX") as mock_vmx,
        patch("dissect.target.container.open") as mock_container_open,
    ):
        mock_vmx.parse.return_value = mock_vmx
        mock_vmx.disks.return_value = disks
        yield mock_container_open


@pytest.fixture
def mock_vmwarevm_dir(tmp_path: Path) -> Path:
    vm_path = tmp_path / "Test.vmwarevm"
    vm_path.mkdir()
    vmx_path = vm_path / "Test.vmx"
    vmx_path.touch()

    return vm_path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target], mock_vmwarevm_dir: Path) -> None:
    """Test that we correctly use ``VmwarevmLoader`` when opening a ``Target``."""
    path = mock_vmwarevm_dir / "Test.vmx"

    with patch("dissect.target.container.open"), patch("dissect.target.target.Target.apply"):
        target = opener(path)
        assert isinstance(target._loader, VmxLoader)
        assert target.path == path


def test_loader(mock_vmwarevm_dir: Path) -> None:
    (mock_vmwarevm_dir / "mock.vmdk").touch()

    with _mock_vmx_and_container_open(["mock.vmdk"]) as mock_container_open:
        loader = loader_open(mock_vmwarevm_dir / "Test.vmx")
        assert isinstance(loader, VmxLoader)

        t = Target()
        loader.map(t)

        assert len(t.disks) == 1
        mock_container_open.assert_called_with(mock_vmwarevm_dir / "mock.vmdk")


def test_missing_disk(mock_vmwarevm_dir: Path, caplog: pytest.LogCaptureFixture) -> None:
    t = Target()

    with _mock_vmx_and_container_open(["mock.vmdk"]), caplog.at_level(logging.DEBUG, t.log.name):
        loader = loader_open(mock_vmwarevm_dir / "Test.vmx")
        assert isinstance(loader, VmxLoader)

        loader.map(t)
        assert len(t.disks) == 0
        assert "Disk not found: mock.vmdk" in caplog.text


def test_missing_snapshots(mock_vmwarevm_dir: Path, caplog: pytest.LogCaptureFixture) -> None:
    (mock_vmwarevm_dir / "mock.vmdk").touch()
    (mock_vmwarevm_dir / "mock-000001.vmdk").touch()

    t = Target()

    with (
        _mock_vmx_and_container_open(["mock-000002.vmdk"]) as mock_container_open,
        caplog.at_level(logging.DEBUG, t.log.name),
    ):
        loader = loader_open(mock_vmwarevm_dir / "Test.vmx")
        assert isinstance(loader, VmxLoader)

        loader.map(t)

        assert len(t.disks) == 1
        mock_container_open.assert_called_with(mock_vmwarevm_dir / "mock-000001.vmdk")

        assert "Disk not found but seems to be a snapshot, trying previous snapshots: mock-000002.vmdk" in caplog.text
        assert "Trying to load snapshot: mock-000001.vmdk" in caplog.text
        assert (
            "Missing disk(s) but continuing with found snapshot: mock-000001.vmdk (missing mock-000002.vmdk)"
            in caplog.text
        )


def test_missing_snapshots_base(mock_vmwarevm_dir: Path, caplog: pytest.LogCaptureFixture) -> None:
    (mock_vmwarevm_dir / "mock.vmdk").touch()

    t = Target()

    with (
        _mock_vmx_and_container_open(["mock-000002.vmdk"]) as mock_container_open,
        caplog.at_level(logging.DEBUG, t.log.name),
    ):
        loader = loader_open(mock_vmwarevm_dir / "Test.vmx")
        assert isinstance(loader, VmxLoader)

        loader.map(t)

        assert len(t.disks) == 1
        mock_container_open.assert_called_with(mock_vmwarevm_dir / "mock.vmdk")

        assert "Disk not found but seems to be a snapshot, trying previous snapshots: mock-000002.vmdk" in caplog.text
        assert "Trying to load snapshot: mock-000001.vmdk" in caplog.text
        assert "Trying to load snapshot: mock.vmdk" in caplog.text
        assert (
            "Missing disk(s) but continuing with found snapshot: mock.vmdk (missing mock-000002.vmdk, mock-000001.vmdk)"
            in caplog.text
        )


def test_missing_all_snapshots(mock_vmwarevm_dir: Path, caplog: pytest.LogCaptureFixture) -> None:
    t = Target()

    with _mock_vmx_and_container_open(["mock-000001.vmdk"]), caplog.at_level(logging.DEBUG, t.log.name):
        loader = loader_open(mock_vmwarevm_dir / "Test.vmx")
        assert isinstance(loader, VmxLoader)

        loader.map(t)

        assert len(t.disks) == 0

        assert "Failed to find previous snapshot for disk: mock-000001.vmdk" in caplog.text
