from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.filesystem import VirtualFile, VirtualFilesystem
from dissect.target.plugins.filesystem.resolver import ResolverPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("test_target", "resolve_func"),
    [
        (
            "target_win",
            "resolve_windows",
        ),
        (
            "target_unix",
            "resolve_default",
        ),
    ],
)
def test_resolve(target_win: Target, target_unix: Target, test_target: str, resolve_func: str) -> None:
    targets = {
        "target_win": target_win,
        "target_unix": target_unix,
    }
    test_target = targets.get(test_target)
    resolver_plugin = ResolverPlugin(test_target)
    with patch.object(resolver_plugin, resolve_func, autospec=True):
        resolver_plugin.resolve("/some/path", "some_user")
        resolve_func = getattr(resolver_plugin, resolve_func)
        resolve_func.assert_called()


def test_resolve_no_path(target_win: Target) -> None:
    path = ""
    assert target_win.resolve(path) == target_win.fs.path(path)


def mock_expand_env(path: str, user_sid: str | None = None) -> str:
    return path


def mock_user_env(user: str | None) -> OrderedDict[str, str]:
    path_envs = {
        None: OrderedDict(
            (("%path%", "sysvol/windows/syswow64"),),
        ),
        "1337": OrderedDict(
            (("%path%", "sysvol\\some_dir\\;sysvol\\other_dir\\"),),
        ),
    }

    return path_envs.get(user, OrderedDict())


@pytest.mark.parametrize(
    ("path", "user", "resolved_path"),
    [
        (
            "",
            None,
            "",
        ),
        (
            "/systemroot/test",
            None,
            "/%systemroot%/test",
        ),
        (
            "\\systemroot\\test",
            None,
            "/%systemroot%/test",
        ),
        (
            "/??/C:/test",
            None,
            "C:/test",
        ),
        (
            "\\??\\C:\\test",
            None,
            "C:/test",
        ),
        (
            '"\\??\\C:\\windows\\system32\\calc.exe" -args',
            None,
            "C:/windows/system32/calc.exe",
        ),
        (
            "\\\\?\\C:\\Users\\Testpath\\Testfile",
            None,
            "C:/Users/Testpath/Testfile",
        ),
        (
            "C:/windows/system32/calc.exe -args",
            None,
            "C:/windows/system32/calc.exe",
        ),
        (
            "C:/some dir with spaces/calc.exe",
            None,
            "C:/some dir with spaces/calc.exe",
        ),
        (
            "C:/some dir with spaces/calc.exe -with -arguments",
            None,
            "C:/some dir with spaces/calc.exe",
        ),
        (
            "C:/windows/system32/calc -args",
            None,
            "C:/windows/system32/calc.exe",
        ),
        (
            "calc -args",
            None,
            "sysvol/windows/syswow64/calc.exe",
        ),
        (
            "calc",
            "no_env_use_fallback",
            "sysvol/windows/system32/calc.exe",
        ),
        (
            "calc",
            "1337",
            "sysvol/some_dir/calc.exe",
        ),
        (
            "foo",
            "1337",
            "sysvol/other_dir/foo.bat",
        ),
    ],
)
def test_resolve_windows(
    target_win: Target, path: str, fs_win: VirtualFilesystem, user: str | None, resolved_path: str
) -> None:
    fs_win.map_file_entry("windows/system32/calc.exe", VirtualFile(fs_win, "windows/system32/calc.exe", None))
    fs_win.map_file_entry("windows/syswow64/calc.exe", VirtualFile(fs_win, "windows/syswow64/calc.exe", None))
    fs_win.map_file_entry("some dir with spaces/calc.exe", VirtualFile(fs_win, "some dir with spaces/calc.exe", None))
    fs_win.map_file_entry("some_dir/calc.exe", VirtualFile(fs_win, "some_dir/calc.exe", None))
    fs_win.map_file_entry("other_dir/calc.exe", VirtualFile(fs_win, "other_dir/calc.exe", None))
    fs_win.map_file_entry("other_dir/foo.bat", VirtualFile(fs_win, "other_dir/foo.bat", None))

    resolver_plugin = ResolverPlugin(target_win)
    assert target_win.pathext is not None  # This will load the EnvironmentVariablePlugin
    env_plugin = next(plugin for plugin in target_win._plugins if type(plugin).__name__ == "EnvironmentVariablePlugin")
    with (
        patch.object(env_plugin, "_get_pathext", return_value={".exe", ".bat"}, autospec=True),
        patch.object(env_plugin, "expand_env", side_effect=mock_expand_env, autospec=True),
        patch.object(env_plugin, "user_env", side_effect=mock_user_env, autospec=True),
    ):
        assert resolver_plugin.resolve_windows(path, user_sid=user) == resolved_path


@pytest.mark.parametrize(
    ("path", "user", "resolved_path"),
    [
        (
            "",
            None,
            "",
        ),
        (
            "/foo/bar",
            None,
            "/foo/bar",
        ),
        (
            "/foo/",
            None,
            "/foo/",
        ),
        (
            "//foo//bar",
            1337,
            "/foo/bar",
        ),
    ],
)
def test_resolve_default(target_unix: Target, path: str, user: str, resolved_path: str) -> None:
    resolver_plugin = ResolverPlugin(target_unix)
    assert resolver_plugin.resolve_default(path, user_id=user) == resolved_path
