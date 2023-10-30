import tarfile
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from dissect.target.loaders.ova import OvaLoader
from dissect.target.target import Target


@patch("dissect.target.loaders.ovf.container")
@patch("dissect.target.loaders.ovf.ovf.OVF")
def test_ova_loader(OVF: MagicMock, container: MagicMock, target_bare: Target, tmp_path: Path):
    tf = tarfile.open((tmp_path / "test.ova"), "w")
    tf.addfile(tarfile.TarInfo("test.ovf"), b"")
    tf.addfile(tarfile.TarInfo("disk.vmdk"), b"")
    tf.close()

    OVF.return_value = OVF
    OVF.disks.return_value = ["disk.vmdk"]
    container.open.return_value = MagicMock()

    ova_loader = OvaLoader(tmp_path / "test.ova")
    ova_loader.map(target_bare)

    assert len(target_bare.disks) == 1
    assert container.open.mock_calls == [call(ova_loader.base_dir / "disk.vmdk")]
