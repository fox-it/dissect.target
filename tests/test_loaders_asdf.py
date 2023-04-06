from pathlib import Path

from dissect.target import Target
from dissect.target.loaders.asdf import AsdfLoader

from ._utils import absolute_path


def test_asdf_loader_metadata(mock_target: Target):
    asdf_path = Path(absolute_path("data/loaders/asdf/metadata.asdf"))

    loader = AsdfLoader(asdf_path)
    loader.map(mock_target)

    assert len(mock_target.filesystems) == 0

    assert list(map(str, mock_target.fs.path("/").rglob("*"))) == [
        "/$asdf$",
        "/$asdf$/file_1",
        "/$asdf$/dir",
        "/$asdf$/dir/file_2",
    ]
