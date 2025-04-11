from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.loaders.asdf import AsdfLoader
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_asdf_loader_metadata(target_bare: Target) -> None:
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
