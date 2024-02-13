from __future__ import annotations

import urllib
from pathlib import Path
from typing import Optional

import pytest

from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.loaderutil import extract_path_info


@pytest.mark.parametrize(
    "path, expected",
    [
        # None objects fall through (BC)
        (None, (None, None)),
        # Path objects fall through (BC/DRY)
        (Path("path"), (Path("path"), None)),
        (TargetPath(DirectoryFilesystem("/")), (TargetPath(DirectoryFilesystem("/")), None)),
        # Strings get upgraded to Paths
        ("/path/to/file", (Path("/path/to/file"), None)),
        # URIs get converted to Path extracted from path part and a ParseResult
        (
            "tar:///folder/file.tar.gz",
            (Path("/folder/file.tar.gz"), urllib.parse.urlparse("tar:///folder/file.tar.gz")),
        ),
        (
            "tar://relative/folder/file.tar.gz",
            (Path("relative/folder/file.tar.gz"), urllib.parse.urlparse("tar://relative/folder/file.tar.gz")),
        ),
        ("tar://~/file.tar.gz", (Path("~/file.tar.gz").expanduser(), urllib.parse.urlparse("tar://~/file.tar.gz"))),
        # But not if the URI has a faux scheme
        ("C:\\path\\to\\file", (Path("C:\\path\\to\\file"), None)),
    ],
)
def test_extract_path_info(
    path: Path | str, expected: tuple[Optional[Path], Optional[urllib.parse.ParseResult[str]]]
) -> None:
    assert extract_path_info(path) == expected
