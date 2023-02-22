from collections import OrderedDict
from unittest.mock import patch

import pytest

from dissect.target.filesystem import VirtualFile
from dissect.target.plugins.filesystem.resolver import ResolverPlugin


@pytest.fixture
def extended_win_fs(fs_win):
    fs_win.map_file_entry("windows/system32/calc.exe", VirtualFile(fs_win, "windows/system32/calc.exe", None))
    fs_win.map_file_entry("windows/syswow64/calc.exe", VirtualFile(fs_win, "windows/syswow64/calc.exe", None))
    fs_win.map_file_entry("some dir with spaces/calc.exe", VirtualFile(fs_win, "some dir with spaces/calc.exe", None))
    fs_win.map_file_entry("some_dir/calc.exe", VirtualFile(fs_win, "some_dir/calc.exe", None))
    fs_win.map_file_entry("other_dir/calc.exe", VirtualFile(fs_win, "other_dir/calc.exe", None))
    fs_win.map_file_entry("other_dir/foo.bat", VirtualFile(fs_win, "other_dir/foo.bat", None))

    return fs_win


@pytest.mark.parametrize(
    "test_target, resolve_func",
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
def test_resolver_plugin_resolve(target_win, target_unix, test_target, resolve_func):
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


def test_resolver_plugin_resolve_no_path(target_win):
    path = ""
    assert target_win.resolve(path) is path


def mock_expand_env(path):
    return path


def mock_user_env(user):
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
    "path, user, resolved_path",
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
def test_resolver_plugin_resolve_windows(target_win, extended_win_fs, path, user, resolved_path):
    resolver_plugin = ResolverPlugin(target_win)
    target_win.pathext  # This will load the EnvironmentVariablePlugin
    env_plugin = next(plugin for plugin in target_win._plugins if type(plugin).__name__ == "EnvironmentVariablePlugin")
    with patch.object(env_plugin, "_get_pathext", return_value={".exe", ".bat"}, autospec=True):
        with patch.object(env_plugin, "expand_env", side_effect=mock_expand_env, autospec=True):
            with patch.object(env_plugin, "user_env", side_effect=mock_user_env, autospec=True):
                assert resolver_plugin.resolve_windows(path, user_sid=user) == resolved_path


@pytest.mark.parametrize(
    "path, user, resolved_path",
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
def test_resolver_plugin_resolve_default(target_unix, path, user, resolved_path):
    resolver_plugin = ResolverPlugin(target_unix)
    assert resolver_plugin.resolve_default(path, user_id=user) == resolved_path
