from pathlib import Path
from unittest.mock import patch

from dissect.target.loaders.dir import find_dirs
from dissect.target.loaders.virtuozzo import VirtuozzoLoader

from ._utils import mkdirs


def test_virtuozzo_loader(mock_target, tmpdir_name):
    root = Path(tmpdir_name)
    mkdirs(
        root, 
        [
            "etc", 
            "var", 
            "vz/root/669ef446-683b-11ed-9022-0242ac120002/var",
            "vz/root/669ef446-683b-11ed-9022-0242ac120002/etc",
            "vz/root/669ef446-683b-11ed-9022-0242ac120001/var",
            "vz/root/669ef446-683b-11ed-9022-0242ac120001/etc",
        ]
    )

    os_type, dirs = find_dirs(root)

    assert os_type == "linux"
    assert len(dirs) == 1

    assert VirtuozzoLoader.detect(root)

    loader = VirtuozzoLoader(root)
    loader.map(mock_target)

    assert len(mock_target.filesystems) == 2
