from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


SharepointRecord = TargetRecordDescriptor(
    "macos/sharepoints/entries",
    [
        ("string", "name"),
        ("string", "directory_path"),
        ("string", "smb_name"),
        ("string", "afp_name"),
        ("path", "source"),
    ],
)


class SharepointsPlugin(Plugin):
    """Plugin to parse macOS sharepoint plist files.

    Parses shared folder/mount point configurations from dslocal sharepoint plists.

    Location: /private/var/db/dslocal/nodes/Default/sharepoints/*.plist
    """

    __namespace__ = "sharepoints"

    PLIST_GLOB = "private/var/db/dslocal/nodes/Default/sharepoints/*.plist"

    def __init__(self, target):
        super().__init__(target)
        self._paths = list(self.target.fs.path("/").glob(self.PLIST_GLOB))

    def check_compatible(self) -> None:
        if not self._paths:
            raise UnsupportedPluginError("No sharepoint plist files found")

    def _read_plist(self, path):
        try:
            with path.open("rb") as fh:
                return plistlib.loads(fh.read())
        except Exception:
            return None

    def _get_first(self, data, key, default=""):
        """Get a value from plist data, handling list-wrapped values."""
        val = data.get(key, default)
        if isinstance(val, list):
            return str(val[0]) if val else default
        return str(val) if val is not None else default

    @export(record=SharepointRecord)
    def entries(self) -> Iterator[SharepointRecord]:
        """Parse sharepoint definitions from dslocal plist files."""
        for path in self._paths:
            try:
                data = self._read_plist(path)
                if data is None:
                    continue

                if not isinstance(data, dict):
                    continue

                # Name from dsAttrTypeStandard:RecordName or filename
                name = self._get_first(data, "dsAttrTypeStandard:RecordName", "")
                if not name:
                    # Fall back to filename without extension
                    filename = str(path).rsplit("/", 1)[-1]
                    name = filename.rsplit(".", 1)[0] if "." in filename else filename

                directory_path = self._get_first(data, "dsAttrTypeStandard:DirectoryPath", "")
                if not directory_path:
                    directory_path = self._get_first(data, "directory_path", "")

                smb_name = self._get_first(data, "dsAttrTypeStandard:SMBName", "")
                if not smb_name:
                    smb_name = self._get_first(data, "smb_name", "")

                afp_name = self._get_first(data, "dsAttrTypeStandard:AFPName", "")
                if not afp_name:
                    afp_name = self._get_first(data, "afp_name", "")

                yield SharepointRecord(
                    name=name,
                    directory_path=directory_path,
                    smb_name=smb_name,
                    afp_name=afp_name,
                    source=path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error parsing sharepoint %s: %s", path, e)
