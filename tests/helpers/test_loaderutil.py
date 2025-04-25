from __future__ import annotations

import urllib
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.target.filesystem import Filesystem, VirtualFilesystem
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.loaderutil import (
    add_virtual_ntfs_filesystem,
    extract_path_info,
)

if TYPE_CHECKING:
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("path", "expected"),
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
    path: Path | str, expected: tuple[Path | None, urllib.parse.ParseResult[str] | None]
) -> None:
    assert extract_path_info(path) == expected


@pytest.mark.parametrize(
    ("boot", "mft", "expected_logs"),
    [
        (None, None, []),
        (
            None,
            False,
            [
                "Opened NTFS filesystem from <VirtualFilesystem> but could not find $MFT, skipping",
            ],
        ),
        (None, True, []),
        (
            False,
            None,
            [
                "Failed to load NTFS filesystem from <VirtualFilesystem>, retrying without $Boot file",
                "Opened NTFS filesystem from <VirtualFilesystem> but could not find $MFT, skipping",
            ],
        ),
        (
            False,
            False,
            [
                "Failed to load NTFS filesystem from <VirtualFilesystem>, retrying without $Boot file",
                "Failed to load NTFS filesystem from <VirtualFilesystem> without $Boot file, skipping",
            ],
        ),
        (
            False,
            True,
            [
                "Failed to load NTFS filesystem from <VirtualFilesystem>, retrying without $Boot file",
            ],
        ),
        (
            True,
            None,
            [
                "Opened NTFS filesystem from <VirtualFilesystem> but could not find $MFT, skipping",
            ],
        ),
        (
            True,
            False,
            [
                "Failed to load NTFS filesystem from <VirtualFilesystem>, retrying without $Boot file",
                "Failed to load NTFS filesystem from <VirtualFilesystem> without $Boot file, skipping",
            ],
        ),
        (True, True, []),
    ],
)
def test_virtual_ntfs_resiliency(
    boot: bool | None,
    mft: bool | None,
    expected_logs: list[str],
    target_default: Target,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sentinels = {
        None: None,
        False: Mock(),
        True: Mock(),
    }

    def _try_open(fs: Filesystem, path: str) -> Mock:
        state = None
        if path == "$Boot":
            state = boot
        elif path == "$MFT":
            state = mft
        return sentinels[state]

    def NtfsFilesystem(boot: Mock | None = None, mft: Mock | None = None, **kwargs) -> Mock:
        if boot is sentinels[False] or mft is sentinels[False]:
            raise ValueError("Oopsiewoopsie")

        fake_ntfs = Mock()
        fake_ntfs.ntfs.mft = None

        if mft is sentinels[True]:
            fake_ntfs.ntfs.mft = Mock()

        return fake_ntfs

    vfs = VirtualFilesystem()
    with (
        patch("dissect.target.helpers.loaderutil._try_open", new=_try_open),
        patch("dissect.target.helpers.loaderutil.NtfsFilesystem", new=NtfsFilesystem),
    ):
        add_virtual_ntfs_filesystem(target_default, vfs)

    assert caplog.messages == expected_logs
    assert hasattr(vfs, "ntfs") == (bool(mft))
