from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from unittest.mock import call, patch

from dissect.target.loaders.vmx import VmxLoader

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

    from dissect.target.target import Target


def test_vmx_loader(target_bare: Target, tmp_path: Path) -> None:
    root = tmp_path.resolve()
    vm_path = root / "Test.vmwarevm"
    vm_path.mkdir()
    vmx_path = vm_path / "Test.vmx"
    vmx_path.touch()
    (vm_path / "mock.vmdk").touch()

    with (
        patch("dissect.hypervisor.descriptor.vmx.VMX") as MockVMX,
        patch("dissect.target.loaders.vmx.VmdkContainer") as MockVmdkContainer,
    ):
        MockVMX.parse.return_value = MockVMX
        MockVMX.disks.return_value = ["mock.vmdk"]
        MockVmdkContainer.return_value = MockVmdkContainer

        assert VmxLoader.detect(vmx_path)

        VmxLoader(vmx_path).map(target_bare)
        assert len(target_bare.disks) == 1
        assert MockVmdkContainer.mock_calls == [call(vm_path / "mock.vmdk")]


def test_vmx_loader_missing_disk(target_bare: Target, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    root = tmp_path.resolve()
    vm_path = root / "Test.vmwarevm"
    vm_path.mkdir()
    vmx_path = vm_path / "Test.vmx"
    vmx_path.touch()

    with (
        patch("dissect.hypervisor.descriptor.vmx.VMX") as MockVMX,
        patch("dissect.target.loaders.vmx.VmdkContainer") as MockVmdkContainer,
        caplog.at_level(logging.DEBUG, target_bare.log.name),
    ):
        MockVMX.parse.return_value = MockVMX
        MockVMX.disks.return_value = ["mock.vmdk"]
        MockVmdkContainer.return_value = MockVmdkContainer

        assert VmxLoader.detect(vmx_path)

        VmxLoader(vmx_path).map(target_bare)
        assert len(target_bare.disks) == 0

        assert "Disk not found: mock.vmdk" in caplog.text


def test_vmx_loader_missing_snapshots(target_bare: Target, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    root = tmp_path
    vm_path = root / "Test.vmwarevm"
    vm_path.mkdir()
    vmx_path = vm_path / "Test.vmx"
    vmx_path.touch()
    (vm_path / "mock.vmdk").touch()
    (vm_path / "mock-000001.vmdk").touch()

    with (
        patch("dissect.hypervisor.descriptor.vmx.VMX") as MockVMX,
        patch("dissect.target.loaders.vmx.VmdkContainer") as MockVmdkContainer,
        caplog.at_level(logging.DEBUG, target_bare.log.name),
    ):
        MockVMX.parse.return_value = MockVMX
        MockVMX.disks.return_value = ["mock-000002.vmdk"]
        MockVmdkContainer.return_value = MockVmdkContainer

        VmxLoader(vmx_path).map(target_bare)

        assert len(target_bare.disks) == 1
        assert MockVmdkContainer.mock_calls == [call(vm_path / "mock-000001.vmdk")]

        assert "Disk not found but seems to be a snapshot, trying previous snapshots: mock-000002.vmdk" in caplog.text
        assert "Trying to load snapshot: mock-000001.vmdk" in caplog.text
        assert (
            "Missing disk(s) but continuing with found snapshot: mock-000001.vmdk (missing mock-000002.vmdk)"
            in caplog.text
        )


def test_vmx_loader_missing_snapshots_base(
    target_bare: Target, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    root = tmp_path
    vm_path = root / "Test.vmwarevm"
    vm_path.mkdir()
    vmx_path = vm_path / "Test.vmx"
    vmx_path.touch()
    (vm_path / "mock.vmdk").touch()

    with (
        patch("dissect.hypervisor.descriptor.vmx.VMX") as MockVMX,
        patch("dissect.target.loaders.vmx.VmdkContainer") as MockVmdkContainer,
        caplog.at_level(logging.DEBUG, target_bare.log.name),
    ):
        MockVMX.parse.return_value = MockVMX
        MockVMX.disks.return_value = ["mock-000002.vmdk"]
        MockVmdkContainer.return_value = MockVmdkContainer

        VmxLoader(vmx_path).map(target_bare)

        assert len(target_bare.disks) == 1
        assert MockVmdkContainer.mock_calls == [call(vm_path / "mock.vmdk")]

        assert "Disk not found but seems to be a snapshot, trying previous snapshots: mock-000002.vmdk" in caplog.text
        assert "Trying to load snapshot: mock-000001.vmdk" in caplog.text
        assert "Trying to load snapshot: mock.vmdk" in caplog.text
        assert (
            "Missing disk(s) but continuing with found snapshot: mock.vmdk (missing mock-000002.vmdk, mock-000001.vmdk)"
            in caplog.text
        )


def test_vmx_loader_missing_all_snapshots(
    target_bare: Target, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    root = tmp_path
    vm_path = root / "Test.vmwarevm"
    vm_path.mkdir()
    vmx_path = vm_path / "Test.vmx"
    vmx_path.touch()

    with (
        patch("dissect.hypervisor.descriptor.vmx.VMX") as MockVMX,
        patch("dissect.target.loaders.vmx.VmdkContainer") as MockVmdkContainer,
        caplog.at_level(logging.DEBUG, target_bare.log.name),
    ):
        MockVMX.parse.return_value = MockVMX
        MockVMX.disks.return_value = ["mock-000001.vmdk"]
        MockVmdkContainer.return_value = MockVmdkContainer

        VmxLoader(vmx_path).map(target_bare)

        assert len(target_bare.disks) == 0

        assert "Failed to find previous snapshot for disk: mock-000001.vmdk" in caplog.text
