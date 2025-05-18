from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import call, patch

from dissect.target.loaders.vmwarevm import VmwarevmLoader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.hypervisor.descriptor.vmx import VMX

    from dissect.target.containers.vmdk import VmdkContainer
    from dissect.target.target import Target


@patch("dissect.target.loaders.vmx.VmdkContainer")
@patch("dissect.target.loaders.vmx.vmx.VMX")
def test_vmwarevm_loader(VMX: VMX, VmdkContainer: VmdkContainer, target_bare: Target, tmp_path: Path) -> None:
    root = tmp_path.resolve()
    vm_path = root / "Test.vmwarevm"
    vm_path.mkdir()
    (vm_path / "Test.vmx").touch()
    (vm_path / "mock.vmdk").touch()

    VMX.parse.return_value = VMX
    VMX.disks.return_value = ["mock.vmdk"]
    VmdkContainer.return_value = VmdkContainer

    assert VmwarevmLoader.detect(vm_path)

    VmwarevmLoader(vm_path).map(target_bare)
    assert len(target_bare.disks) == 1
    assert VmdkContainer.mock_calls == [call(vm_path / "mock.vmdk")]
