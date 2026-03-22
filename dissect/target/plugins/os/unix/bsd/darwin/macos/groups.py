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
        ("string", "generateduid"),
        ("string", "members"),
        ("string", "smb_sid"),
        ("varint", "gid"),
        ("string", "name"),
        ("string", "realname"),
        ("path", "source"),
    ],
)


class GroupPlugin(Plugin):
    """macOS group plugin."""

    GROUP_PATH_GLOB = "/var/db/dslocal/nodes/Default/groups/*.plist"

    def __init__(self, target: Target):
        super().__init__(target)
        self.group_files = set()
        self._resolve_files()

    def check_compatible(self) -> None:
        if not self.group_files:
            raise UnsupportedPluginError("No group files found")

    def _resolve_files(self) -> None:
        for file in self.target.fs.glob(self.GROUP_PATH_GLOB):
            self.group_files.add(file)

    @export(record=GroupInfoRecord)
    def groups(self) -> Iterator[GroupInfoRecord]:
        """Yield user account policy information."""
        for file in self.group_files:
            file = self.target.fs.path(file)
            group_data = plistlib.load(file.open())

            if uuid := group_data.get("generateduid"):  # noqa: SIM102
                if len(uuid) == 1:
                    uuid = uuid[0]

            if smb_sid := group_data.get("smb_sid"):  # noqa: SIM102
                if len(smb_sid):
                    smb_sid = smb_sid[0]

            if gid := group_data.get("gid"):  # noqa: SIM102
                if len(gid) == 1:
                    gid = gid[0]

            if members := group_data.get("users"):  # noqa: SIM102
                if len(members) == 1:
                    members = members[0]

            if realname := group_data.get("realname"):  # noqa: SIM102
                if len(realname) == 1:
                    realname = realname[0]

            if name := group_data.get("name"):  # noqa: SIM102
                if len(name) == 1:
                    name = name[0]

            yield GroupInfoRecord(
                generateduid=uuid,
                members=members,
                smb_sid=smb_sid,
                gid=gid,
                name=name,
                realname=realname,
                source=file,
                _target=self.target,
            )
