from __future__ import annotations

from functools import lru_cache
from typing import Iterator, NamedTuple, Union

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import UnixUserRecord, WindowsUserRecord
from dissect.target.plugin import InternalPlugin

UserRecord = Union[UnixUserRecord, WindowsUserRecord]


class UserDetails(NamedTuple):
    user: UserRecord
    home_path: TargetPath | None


class UsersPlugin(InternalPlugin):
    """Internal plugin that provides helper functions for retrieving user details."""

    __namespace__ = "user_details"

    def __init__(self, target: Target):
        super().__init__(target)
        self.find = lru_cache(32)(self.find)

    def check_compatible(self) -> None:
        if not hasattr(self.target, "users"):
            raise UnsupportedPluginError("Unsupported Plugin")

    def find(
        self,
        sid: str | None = None,
        uid: str | None = None,
        username: str | None = None,
        force_case_sensitive: bool = False,
    ) -> UserDetails | None:
        """Find User record matching provided sid, uid or username and return UserDetails object"""
        if all(map(lambda x: x is None, [sid, uid, username])):
            raise ValueError("Either sid or uid or username is expected")

        def is_name_matching(name: str) -> bool:
            if force_case_sensitive or self.target.os != "windows":
                # always do case-sensitive match for non-Windows OSes
                return name == username
            else:
                return name.lower() == username.lower()

        for user in self.target.users():
            if (
                (sid is not None and user.sid == sid)
                or (uid is not None and user.uid == uid)
                or (username is not None and is_name_matching(user.name))
            ):
                return self.get(user)

    def get(self, user: UserRecord) -> UserDetails:
        """Return additional details about the user"""
        # Resolving the user home can not use the user's environment variables,
        # as those depend on the user's home to be known first. So we resolve
        # without providing the user (s)id.
        home_path = self.target.fs.path(self.target.resolve(str(user.home))) if user.home else None
        return UserDetails(user=user, home_path=home_path)

    def all(self) -> Iterator[UserDetails]:
        """Return UserDetails objects for all users found"""
        for user in self.target.users():
            yield self.get(user)

    def all_with_home(self) -> Iterator[UserDetails]:
        """Return UserDetails objects for users that have existing directory set as home directory"""
        for user in self.target.users():
            if user.home:
                user_details = self.get(user)
                if user_details.home_path.exists():
                    yield user_details
