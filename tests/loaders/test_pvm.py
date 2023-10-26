from unittest.mock import call, patch

from dissect.target.loaders.pvm import PvmLoader
from tests._utils import mkdirs


@patch("dissect.target.loaders.pvs.HddContainer")
@patch("dissect.target.loaders.pvs.pvs.PVS")
def test_pvm_loader(PVS, HddContainer, target_bare, tmp_path):
    mkdirs(tmp_path, ["Test.pvm"])
    (tmp_path / "Test.pvm" / "config.pvs").touch()

    PVS.return_value = PVS
    PVS.disks.return_value = ["mock.hdd"]
    HddContainer.return_value = HddContainer

    pvm_loader = PvmLoader(tmp_path / "Test.pvm")
    pvm_loader.map(target_bare)

    assert len(target_bare.disks) == 1
    assert HddContainer.mock_calls == [call(tmp_path.resolve() / "Test.pvm" / "mock.hdd")]
