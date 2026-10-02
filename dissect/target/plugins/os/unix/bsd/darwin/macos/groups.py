from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

GroupInfoRecord = TargetRecordDescriptor(
    "macos/groups",
    [
        ("string[]", "generateduid"),
        ("string[]", "members"),
        ("string[]", "smb_sid"),
        ("varint[]", "gid"),
        ("string[]", "name"),
        ("string[]", "realname"),
        ("path", "source"),
    ],
)


class GroupPlugin(Plugin):
    """macOS group plugin.

    Parses ``/var/db/dslocal/nodes/Default/groups/*.plist`` files, which contain config data for groups.

    References:
        - https://xmcyber.com/blog/introducing-machound-a-solution-to-macos-active-directory-based-attacks/
    """

    GROUP_PATH_GLOB = "/var/db/dslocal/nodes/Default/groups/*.plist"

    def __init__(self, target: Target):
        super().__init__(target)
        self.group_files = self._resolve_files()

    def check_compatible(self) -> None:
        if not self.group_files:
            raise UnsupportedPluginError("No group files found")

    def _resolve_files(self) -> set():
        files = set()
        for file in self.target.fs.glob(self.GROUP_PATH_GLOB):
            files.add(file)
        return files

    @export(record=GroupInfoRecord)
    def groups(self) -> Iterator[GroupInfoRecord]:
        """Return group information.

        Yields GroupInfoRecords with the following fields:

        .. code-block:: text

            generateduid (string[]): Generated unique identifier(s) for the group.
            members (string[]): List of user accounts that are members of the group.
            smb_sid (string[]): SMB security identifier(s) associated with the group.
            gid (varint[]): Group ID(s) assigned to the group.
            name (string[]): Name(s) of the group.
            realname (string[]): Realname(s) of the group.
            source (path): Path to the group plist file.
        """
        for file in self.group_files:
            file = self.target.fs.path(file)
            group_data = plistlib.load(file.open())

            yield GroupInfoRecord(
                generateduid=group_data.get("generateduid"),
                members=group_data.get("users"),
                smb_sid=group_data.get("smb_sid"),
                gid=group_data.get("gid"),
                name=group_data.get("name"),
                realname=group_data.get("realname"),
                source=file,
                _target=self.target,
            )
