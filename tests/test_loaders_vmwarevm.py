from pathlib import Path
from unittest.mock import call, patch

from dissect.hypervisor.descriptor.vmx import VMX

from dissect.target.containers.vmdk import VmdkContainer
from dissect.target.loaders.vmwarevm import VmwarevmLoader
from dissect.target.target import Target

from ._utils import mkdirs


@patch("dissect.target.loaders.vmx.VmdkContainer")
@patch("dissect.target.loaders.vmx.vmx.VMX")
def test_vmwarevm_loader(VMX: VMX, VmdkContainer: VmdkContainer, mock_target: Target, tmp_path: Path):
    root = tmp_path
    mkdirs(root, ["Test.vmwarevm"])
    (root / "Test.vmwarevm" / "Test.vmx").touch()

    VMX.parse.return_value = VMX
    VMX.disks.return_value = ["mock.vmdk"]
    VmdkContainer.return_value = VmdkContainer

    vmwarevm_loader = VmwarevmLoader(root / "Test.vmwarevm")
    vmwarevm_loader.map(mock_target)

    assert len(mock_target.disks) == 1
    assert VmdkContainer.mock_calls == [call(root.resolve() / "Test.vmwarevm" / "mock.vmdk")]
