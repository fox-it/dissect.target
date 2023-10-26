from pathlib import Path

from dissect.target import Target
from dissect.target.loaders.asdf import AsdfLoader
from tests._utils import absolute_path


def test_asdf_loader_metadata(target_bare: Target):
    asdf_path = Path(absolute_path("_data/loaders/asdf/metadata.asdf"))

    loader = AsdfLoader(asdf_path)
    loader.map(target_bare)

    assert len(target_bare.filesystems) == 0

    assert list(map(str, target_bare.fs.path("/").rglob("*"))) == [
        "/$asdf$",
        "/$asdf$/file_1",
        "/$asdf$/dir",
        "/$asdf$/dir/file_2",
    ]
