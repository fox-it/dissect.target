from pathlib import Path
from unittest.mock import call, patch

from dissect.target.loaders.pvm import PvmLoader

from ._utils import mkdirs


@patch("dissect.target.loaders.pvs.HddContainer")
@patch("dissect.target.loaders.pvs.pvs.PVS")
def test_pvm_loader(PVS, HddContainer, mock_target, tmpdir_name):
    root = Path(tmpdir_name)
    mkdirs(root, ["Test.pvm"])
    (root / "Test.pvm" / "config.pvs").touch()

    PVS.return_value = PVS
    PVS.disks.return_value = ["mock.hdd"]
    HddContainer.return_value = HddContainer

    pvm_loader = PvmLoader(root / "Test.pvm")
    pvm_loader.map(mock_target)

    assert len(mock_target.disks) == 1
    assert HddContainer.mock_calls == [call(root.resolve() / "Test.pvm" / "mock.hdd")]
