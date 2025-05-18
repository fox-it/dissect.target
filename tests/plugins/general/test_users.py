from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_users_plugin(target_win_users: Target, fs_win: VirtualFilesystem, tmp_path: Path) -> None:
    users = list(target_win_users.users())
    assert len(users) == 2

    users_details = list(target_win_users.user_details.all())
    assert len(users_details) == 2
    assert {d.user.sid for d in users_details} == {u.sid for u in users}

    assert target_win_users.user_details.find(sid="S-1-5-21-3263113198-3007035898-945866154-1002")
    john = target_win_users.user_details.find(username="John")
    assert john

    details = target_win_users.user_details.get(john.user)
    assert details
    assert details.user == john.user
    assert details.home_path == target_win_users.fs.path("C:/Users/John")

    users_with_home = list(target_win_users.user_details.all_with_home())
    assert len(users_with_home) == 0  # no users have home dirs

    fs_win.map_dir("Users\\John", tmp_path)
    users_with_home = list(target_win_users.user_details.all_with_home())
    assert len(users_with_home) == 1  # only John has a home dir


def test_users_plugin_find_no_params(target_unix_users: Target) -> None:
    with pytest.raises(ValueError, match="Either sid or uid or username is expected"):
        target_unix_users.user_details.find()


def test_users_plugin_find_no_usser(target_unix_users: Target) -> None:
    user_details = target_unix_users.user_details.find(uid=13)
    assert user_details is None


def test_users_plugin_find_uid0(target_unix_users: Target) -> None:
    user_details = target_unix_users.user_details.find(uid=0)
    assert user_details is not None
    assert user_details.user.uid == 0
