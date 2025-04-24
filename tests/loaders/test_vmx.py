import logging
from pathlib import Path
from unittest.mock import call, patch

import pytest
from dissect.hypervisor.descriptor.vmx import VMX

from dissect.target.containers.vmdk import VmdkContainer
from dissect.target.loaders.vmx import VmxLoader
from dissect.target.target import Target


@patch("dissect.target.loaders.vmx.VmdkContainer")
@patch("dissect.target.loaders.vmx.vmx.VMX")
def test_vmx_loader(VMX: VMX, VmdkContainer: VmdkContainer, target_bare: Target, tmp_path: Path) -> None:
    root = tmp_path.resolve()
    vm_path = root / "Test.vmwarevm"
    vm_path.mkdir()
    vmx_path = vm_path / "Test.vmx"
    vmx_path.touch()
    (vm_path / "mock.vmdk").touch()

    VMX.parse.return_value = VMX
    VMX.disks.return_value = ["mock.vmdk"]
    VmdkContainer.return_value = VmdkContainer

    assert VmxLoader.detect(vmx_path)

    VmxLoader(vmx_path).map(target_bare)
    assert len(target_bare.disks) == 1
    assert VmdkContainer.mock_calls == [call(vm_path / "mock.vmdk")]


@patch("dissect.target.loaders.vmx.VmdkContainer")
@patch("dissect.target.loaders.vmx.vmx.VMX")
def test_vmx_loader_missing_disk(
    VMX: VMX, VmdkContainer: VmdkContainer, target_bare: Target, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    root = tmp_path.resolve()
    vm_path = root / "Test.vmwarevm"
    vm_path.mkdir()
    vmx_path = vm_path / "Test.vmx"
    vmx_path.touch()

    VMX.parse.return_value = VMX
    VMX.disks.return_value = ["mock.vmdk"]
    VmdkContainer.return_value = VmdkContainer

    assert VmxLoader.detect(vmx_path)

    VmxLoader(vmx_path).map(target_bare)
    assert len(target_bare.disks) == 0

    assert "Disk not found: mock.vmdk" in caplog.text


@patch("dissect.target.loaders.vmx.VmdkContainer")
@patch("dissect.target.loaders.vmx.vmx.VMX")
def test_vmx_loader_missing_snapshots(
    VMX: VMX, VmdkContainer: VmdkContainer, target_bare: Target, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    root = tmp_path
    vm_path = root / "Test.vmwarevm"
    vm_path.mkdir()
    vmx_path = vm_path / "Test.vmx"
    vmx_path.touch()
    (vm_path / "mock.vmdk").touch()
    (vm_path / "mock-000001.vmdk").touch()

    VMX.parse.return_value = VMX
    VMX.disks.return_value = ["mock-000002.vmdk"]
    VmdkContainer.return_value = VmdkContainer

    caplog.set_level(logging.DEBUG)

    VmxLoader(vmx_path).map(target_bare)
    assert len(target_bare.disks) == 1
    assert VmdkContainer.mock_calls == [call(vm_path / "mock-000001.vmdk")]

    assert "Disk not found but seems to be a snapshot, trying previous snapshots: mock-000002.vmdk" in caplog.text
    assert "Trying to load snapshot: mock-000001.vmdk" in caplog.text
    assert (
        "Missing disk(s) but continuing with found snapshot: mock-000001.vmdk (missing mock-000002.vmdk)" in caplog.text
    )


@patch("dissect.target.loaders.vmx.VmdkContainer")
@patch("dissect.target.loaders.vmx.vmx.VMX")
def test_vmx_loader_missing_snapshots_base(
    VMX: VMX, VmdkContainer: VmdkContainer, target_bare: Target, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    root = tmp_path
    vm_path = root / "Test.vmwarevm"
    vm_path.mkdir()
    vmx_path = vm_path / "Test.vmx"
    vmx_path.touch()
    (vm_path / "mock.vmdk").touch()

    VMX.parse.return_value = VMX
    VMX.disks.return_value = ["mock-000002.vmdk"]
    VmdkContainer.return_value = VmdkContainer

    caplog.set_level(logging.DEBUG)

    VmxLoader(vmx_path).map(target_bare)
    assert len(target_bare.disks) == 1
    assert VmdkContainer.mock_calls == [call(vm_path / "mock.vmdk")]

    assert "Disk not found but seems to be a snapshot, trying previous snapshots: mock-000002.vmdk" in caplog.text
    assert "Trying to load snapshot: mock-000001.vmdk" in caplog.text
    assert "Trying to load snapshot: mock.vmdk" in caplog.text
    assert (
        "Missing disk(s) but continuing with found snapshot: mock.vmdk (missing mock-000002.vmdk, mock-000001.vmdk)"
        in caplog.text
    )


@patch("dissect.target.loaders.vmx.VmdkContainer")
@patch("dissect.target.loaders.vmx.vmx.VMX")
def test_vmx_loader_missing_all_snapshots(
    VMX: VMX, VmdkContainer: VmdkContainer, target_bare: Target, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    root = tmp_path
    vm_path = root / "Test.vmwarevm"
    vm_path.mkdir()
    vmx_path = vm_path / "Test.vmx"
    vmx_path.touch()

    VMX.parse.return_value = VMX
    VMX.disks.return_value = ["mock-000001.vmdk"]
    VmdkContainer.return_value = VmdkContainer

    caplog.set_level(logging.DEBUG)

    VmxLoader(vmx_path).map(target_bare)
    assert len(target_bare.disks) == 0

    assert "Failed to find previous snapshot for disk: mock-000001.vmdk" in caplog.text
