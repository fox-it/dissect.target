from __future__ import annotations

from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, NamedTuple, Union

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import (
    IOSUserRecord,
    MacOSUserRecord,
    UnixUserRecord,
    WindowsUserRecord,
)
from dissect.target.plugin import InternalPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.target import Target

UserRecord = Union[UnixUserRecord, WindowsUserRecord, MacOSUserRecord, IOSUserRecord]


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
        uid: int | None = None,
        username: str | None = None,
        force_case_sensitive: bool = False,
    ) -> UserDetails | None:
        """Find user record by ``sid``, ``uid`` or ``username`` and return :class:`UserDetails` object."""
        if all(x is None for x in [sid, uid, username]):
            raise ValueError("Either sid or uid or username is expected")

        def is_name_matching(name: str) -> bool:
            if force_case_sensitive or self.target.os != "windows":
                # always do case-sensitive match for non-Windows OSes
                return name == username
            return name.lower() == username.lower()

        for user in self.target.users():
            if (
                (sid is not None and user.sid == sid)
                or (uid is not None and user.uid == uid)
                or (username is not None and is_name_matching(user.name))
            ):
                return self.get(user)

        return None

    def get(self, user: UserRecord) -> UserDetails:
        """Return additional details about the user."""
        # Resolving the user home can not use the user's environment variables,
        # as those depend on the user's home to be known first. So we resolve
        # without providing the user (s)id.
        home_path = self.target.resolve(str(user.home)) if user.home else None
        return UserDetails(user=user, home_path=home_path)

    def all(self) -> Iterator[UserDetails]:
        """Return :class:`UserDetails` objects for all users found."""
        for user in self.target.users():
            yield self.get(user)

    def all_with_home(self) -> Iterator[UserDetails]:
        """Return :class:`UserDetails` objects for users that have existing directory set as home directory."""

        seen: set[TargetPath] = set()
        try:
            for user in self.target.users():
                if user.home:
                    user_details = self.get(user)
                    if user_details.home_path.exists():
                        seen.add(user_details.home_path)
                        yield user_details
        except Exception as e:
            self.target.log.warning("Failed to retrieve user details, falling back to hardcoded locations")
            self.target.log.debug("", exc_info=e)

        # Iterate over misc home directories
        for misc_home_dir, user_criterion in self.target.misc_user_paths():
            # We skip the entry if no user can be found.
            # We cannot use set membership check here because of https://github.com/fox-it/dissect.target/issues/1203
            if any(seen_path.samefile(misc_home_dir) for seen_path in seen) or not user_criterion:
                continue

            if (user_details := self.find(**{user_criterion[0]: user_criterion[1]})) is None:
                continue

            yield UserDetails(user=user_details.user, home_path=misc_home_dir)
            seen.add(misc_home_dir)

    @cached_property
    def all_home_paths(self) -> Iterator[TargetPath]:
        """Return all home directories of users, including miscellaneous user directories that may not be linked to discovered local users."""  # noqa: E501

        seen: set[TargetPath] = set()
        try:
            for user in self.target.users():
                if user.home and (home_path := self.target.resolve(str(user.home))).exists():
                    yield home_path
                    seen.add(home_path)
        except Exception as e:
            self.target.log.warning("Failed to retrieve user details, falling back to hardcoded locations")
            self.target.log.debug("", exc_info=e)

        # Iterate over misc home directories
        for misc_home_dir, _ in self.target.misc_user_paths():
            # We cannot use set membership check here because of https://github.com/fox-it/dissect.target/issues/1203
            if not any(seen_path.samefile(misc_home_dir) for seen_path in seen):
                yield misc_home_dir
                seen.add(misc_home_dir)
