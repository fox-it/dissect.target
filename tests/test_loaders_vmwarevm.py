from pathlib import Path
from unittest.mock import call, patch

from dissect.target.loaders.vmwarevm import VmwarevmLoader

from ._utils import mkdirs


@patch("dissect.target.loaders.vmx.VmdkContainer")
@patch("dissect.target.loaders.vmx.vmx.VMX")
def test_pvm_loader(VMX, VmdkContainer, mock_target, tmpdir_name):
    root = Path(tmpdir_name)
    mkdirs(root, ["Test.vmwarevm"])
    (root / "Test.vmwarevm" / "Test.vmx").touch()

    VMX.parse.return_value = VMX
    VMX.disks.return_value = ["mock.vmdk"]
    VmdkContainer.return_value = VmdkContainer

    vmwarevm_loader = VmwarevmLoader(root / "Test.vmwarevm")
    vmwarevm_loader.map(mock_target)

    assert len(mock_target.disks) == 1
    assert VmdkContainer.mock_calls == [call(root.resolve() / "Test.vmwarevm" / "mock.vmdk")]
