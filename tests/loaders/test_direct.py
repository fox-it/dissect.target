import logging
from pathlib import Path
from zipfile import ZipFile

import pytest

from dissect.target import Target
from tests._utils import absolute_path


def test_direct_overlap_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Assert direct raise warning in case sensitive mode if some files overlap
    We must uncompress files in a temporary directory as having two files with same name
    would cause issue with git on case insensitive fs.
    """
    ZipFile(absolute_path("_data/loaders/direct/overlap.zip")).extractall(tmp_path)
    if len(list((tmp_path / "overlap").iterdir())) < 2:
        pytest.skip("Test running on an insensitive fs")
    with caplog.at_level(logging.WARNING):
        _ = Target.open_direct([tmp_path], case_sensitive=True)
        assert (
            "Direct mode used in case insensitive mode, but this will cause files overlap, "
            "consider using --direct-sensitive" not in caplog.text
        )
        _ = Target.open_direct([tmp_path], case_sensitive=False)
        assert (
            "Direct mode used in case insensitive mode, but this will cause files overlap, "
            "consider using --direct-sensitive" in caplog.text
        )
