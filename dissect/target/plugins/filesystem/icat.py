from __future__ import annotations

import shutil
import sys

import dissect.extfs.exceptions
import dissect.ntfs.exceptions
import dissect.xfs.exceptions

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, arg, export


class ICatPlugin(Plugin):
    """Plugin to output the contents of a file based on its MFT segment or inode number."""

    FS_SUPPORTED = ("ntfs", "xfs", "ext", "virtual")

    def check_compatible(self) -> None:
        filesystems = self.target.filesystems
        if not any(fs.__type__ in self.FS_SUPPORTED for fs in filesystems):
            raise UnsupportedPluginError("No supported filesystems found")

    @arg("-i", "--inode", "--segment", dest="inum", type=int, required=True, help="MFT segment or inode number")
    @arg(
        "--fs",
        type=int,
        help="optional filesystem index, zero indexed. Defaults to the 'sysvol' or '/' filesystem otherwise",
    )
    @arg("--ads", default="", help="Alternate Data Stream name")
    @export(output="none")
    def icat(self, inum: int, fs: int | None, ads: str) -> None:
        """Output the contents of a file based on its MFT segment or inode number. Supports Alternate Data Streams

        Example:
            .. code-block::

                # outputs contents of segment defaults to 'sysvol'
                target-query <TARGET> -f icat --segment 96997

                # outputs contents of inode defaults to '/'
                target-query <TARGET> -f icat --inode 50947

                # outputs contents of segment's ADS
                target-query <TARGET> -f icat --segment 96997 --ads Zone.Identifier

                # outputs contents of segment in filesystem 3 of target
                target-query <TARGET> -f icat --fs 3 --segment 96997

                # outputs contents of inode in filesystem 2 of target
                target-query <TARGET> -f icat --fs 2 --inode 50947
        """

        open_as = None
        try:
            if fs is not None:
                try:
                    filesystem = self.target.filesystems[fs]
                except IndexError:
                    self.target.log.exception("%s does not have a filesystem with index number: %s", self.target, fs)
                    return
            else:
                if "sysvol" in self.target.fs.mounts:
                    filesystem = self.target.fs.mounts["sysvol"]
                    # In some cases the fstype of sysvol can be virtual. For this
                    # case we set the open_as sentinel so the code
                    # opening the filesystem handle know how to open it.
                    open_as = "ntfs"
                elif "/" in self.target.fs.mounts:
                    filesystem = self.target.fs.mounts["/"]
                else:
                    self.target.log.exception(
                        '%s does not contain mountpoints "sysvol" or "/" '
                        'specify your own filesystem using the "--fs" option',
                        self.target,
                    )
                    return

            if filesystem.__type__ == "ntfs" or open_as == "ntfs":
                fh = filesystem.ntfs.mft(inum).open(ads)
            elif filesystem.__type__ == "ext":
                fh = filesystem.extfs.get_inode(inum).open()
            elif filesystem.__type__ == "xfs":
                fh = filesystem.xfs.get_inode(inum).open()
            else:
                self.target.log.exception('Unsupported FS type "%s"', filesystem.__type__)
                return

            shutil.copyfileobj(fh, sys.stdout.buffer)

        except (
            dissect.ntfs.exceptions.Error,
            dissect.extfs.exceptions.Error,
            dissect.xfs.exceptions.Error,
        ):
            # For example, ntfs.exceptions.VolumeNotAvailableError that gets thrown
            # when you try to icat a file from an acquire which is non-resident
            self.target.log.exception(
                "%s failed to get contents of file with segment / inode number %s from filesystem %s (ADS: %s)",
                self.target,
                inum,
                filesystem,
                ads,
            )
