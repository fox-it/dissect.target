from collections import namedtuple
from typing import Generator

from flow.record import RecordDescriptor

from dissect.target.plugin import InternalPlugin

UserDetails = namedtuple("UserDetails", "user home_path")


class UsersPlugin(InternalPlugin):
    """Internal plugin that provides helper functions for retrieving user details."""

    __namespace__ = "user_details"

    def check_compatible(self) -> bool:
        return hasattr(self.target, "users")

    def find(self, sid: str = None, uid: str = None, username: str = None, force_case_sensitive=False) -> UserDetails:
        """Find User record matching provided sid, uid or username and return UserDetails object"""
        if sum(bool(i) for i in [sid, uid, username]) != 1:
            raise ValueError("Either sid or uid or username is expected")

        def is_name_matching(user):
            if force_case_sensitive or self.target.os != "windows":
                # always do case-sensitive match for non-Windows OSes
                return user.name == username
            else:
                return user.name.lower() == username.lower()

        for user in self.target.users():
            if (sid and user.sid == sid) or (uid and user.uid == uid) or (username and is_name_matching(user)):
                return self.get(user)

    def get(self, user: RecordDescriptor) -> UserDetails:
        """Return additional details about the user"""
        home_path = self.target.fs.path(self.target.resolve(user.home)) if user.home else None
        return UserDetails(user=user, home_path=home_path)

    def all(self) -> Generator[UserDetails, None, None]:
        """Return UserDetails objects for all users found"""
        for user in self.target.users():
            yield self.get(user)

    def all_with_home(self) -> Generator[UserDetails, None, None]:
        """Return UserDetails objects for users that have existing directory set as home directory"""
        for user in self.target.users():
            if user.home:
                user_details = self.get(user)
                if user_details.home_path.exists():
                    yield user_details
