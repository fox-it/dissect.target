from __future__ import annotations

import warnings
from typing import TYPE_CHECKING

from dissect.target.plugin import Plugin, arg, export
from dissect.target.plugins.filesystem.ntfs.mft import MftPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator


class MftTimelinePlugin(Plugin):
    """NTFS MFT timeline plugin."""

    def check_compatible(self) -> None:
        MftPlugin(self.target).check_compatible()

    @export(output="yield")
    @arg("--ignore-dos", action="store_true", help="ignore DOS file names")
    def mft_timeline(self, ignore_dos: bool = False) -> Iterator[str]:
        """Return the MFT records of all NTFS filesystems in a human readable format (unsorted) (deprecated, use mft.timeline).

        The Master File Table (MFT) contains metadata about every file and folder on a NFTS filesystem.

        If the filesystem is part of a virtual NTFS filesystem (a ``VirtualFilesystem`` with the MFT properties
        added to it through a "fake" ``NtfsFilesystem``), the paths returned in the MFT records are based on the
        mount point of the ``VirtualFilesystem``. This ensures that the proper original drive letter is used when
        available.
        When no drive letter can be determined, the path will show as e.g. ``\\$fs$\\fs0``.

        References:
            - https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table
        """  # noqa: E501
        warnings.warn(
            "The `mft_timeline` function is deprecated in favor of `mft.timeline` and will be removed in dissect.target 3.24",  # noqa: E501
            FutureWarning,
            stacklevel=2,
        )
        return MftPlugin(self.target).timeline(ignore_dos)
