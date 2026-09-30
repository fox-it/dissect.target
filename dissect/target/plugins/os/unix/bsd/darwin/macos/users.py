from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


LocalUserRecord = TargetRecordDescriptor(
    "macos/localusers/entry",
    [
        ("string", "username"),
        ("string", "uid"),
        ("string", "gid"),
        ("string", "realname"),
        ("string", "home"),
        ("string", "shell"),
        ("path", "source"),
    ],
)


class MacOSLocalUsersPlugin(Plugin):
    """Plugin to parse macOS local user account plists.

    Location: /private/var/db/dslocal/nodes/Default/users/*.plist
    """

    __namespace__ = "localusers"

    USER_GLOBS = [
        "private/var/db/dslocal/nodes/Default/users/*.plist",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._user_paths = []
        for pattern in self.USER_GLOBS:
            for path in self.target.fs.path("/").glob(pattern):
                self._user_paths.append(path)

    def check_compatible(self) -> None:
        if not self._user_paths:
            raise UnsupportedPluginError("No local user plist files found")

    @export(record=LocalUserRecord)
    def entries(self) -> Iterator[LocalUserRecord]:
        """Parse local user account plists from dslocal."""
        for user_path in self._user_paths:
            try:
                with user_path.open("rb") as fh:
                    data = plistlib.loads(fh.read())

                username = user_path.name.replace(".plist", "")

                uid_list = data.get("uid", [])
                gid_list = data.get("gid", [])
                realname_list = data.get("realname", [])
                home_list = data.get("home", [])
                shell_list = data.get("shell", [])

                yield LocalUserRecord(
                    username=username,
                    uid=str(uid_list[0]) if uid_list else "",
                    gid=str(gid_list[0]) if gid_list else "",
                    realname=str(realname_list[0]) if realname_list else "",
                    home=str(home_list[0]) if home_list else "",
                    shell=str(shell_list[0]) if shell_list else "",
                    source=user_path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error parsing user plist %s: %s", user_path, e)
