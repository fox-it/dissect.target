from pathlib import Path
from unittest.mock import MagicMock, call, patch

from dissect.target.loaders.ovf import OvfLoader
from dissect.target.target import Target


@patch("dissect.target.loaders.ovf.container")
@patch("dissect.target.loaders.ovf.ovf.OVF")
def test_ovf_loader(OVF: MagicMock, container: MagicMock, target_bare: Target, tmp_path: Path):
    (tmp_path / "test.ovf").touch()

    OVF.return_value = OVF
    OVF.disks.return_value = ["disk.vmdk"]
    container.open.return_value = MagicMock()

    ovf_loader = OvfLoader(tmp_path / "test.ovf")
    ovf_loader.map(target_bare)

    assert len(target_bare.disks) == 1
    assert container.open.mock_calls == [call(tmp_path.resolve() / "disk.vmdk")]
