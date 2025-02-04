from pathlib import Path

from dissect.target.loaders.vbk import VBKLoader
from dissect.target.target import Target
from tests._utils import absolute_path


def test_vbk_loader(target_default: Target):
    archive_path = Path(absolute_path("_data/loaders/vbk/test9.vbk"))

    loader = VBKLoader(archive_path)
    loader.map(target_default)
    target_default.apply()

    assert len(target_default.filesystems) == 1

    test_file = target_default.fs.path(
        "/6745a759-2205-4cd2-b172-8ec8f7e60ef8 (78a5467d-87f5-8540-9a84-7569ae2849ad_2d1bb20f-49c1-485d-a689-696693713a5a)/summary.xml")

    assert test_file.exists()
    assert len(test_file.open().read()) > 0
