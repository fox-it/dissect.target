from pathlib import Path
from dissect.target.filesystems.containerimage import ContainerImageFilesystem
from tests._utils import absolute_path


def test_container_image_filesystem() -> None:
    """test if we map a container image correctly."""

    path = Path(absolute_path("_data/loaders/containerimage/alpine.tar"))
    fs = ContainerImageFilesystem(path)

    assert fs.__type__ == "container_image"
    assert fs.name == "alpine:latest"
    assert fs.manifest["Layers"] == ['blobs/sha256/a0904247e36a7726c03c71ee48f3e64462021c88dafeb13f37fdaf613b27f11c']
    assert fs.config["created"] == '2025-01-08T12:07:30Z'
    assert len(fs.layers) == 3
    assert sorted(list(map(str, fs.path("/").iterdir()))) == [
        '/$fs$',
        '/bin',
        '/dev',
        '/etc',
        '/home',
        '/lib',
        '/media',
        '/mnt',
        '/opt',
        '/proc',
        '/root',
        '/run',
        '/sbin',
        '/srv',
        '/sys',
        '/tmp',
        '/usr',
        '/var',
    ]
