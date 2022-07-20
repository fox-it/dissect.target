from dissect.target.filesystem import VirtualFile


def test_resolver_plugin(target_win, fs_win):
    assert target_win.resolve("") == ""
    assert target_win.resolve("/systemroot/test") == "/%systemroot%/test"
    assert target_win.resolve("\\systemroot\\test") == "/%systemroot%/test"
    assert target_win.resolve("/??/C:/test") == "C:/test"
    assert target_win.resolve("\\??\\C:\\test") == "C:/test"

    fs_win.map_file_entry("windows/system32/calc.exe", VirtualFile(fs_win, "windows/system32/calc.exe", None))
    fs_win.map_file_entry("some dir with spaces/calc.exe", VirtualFile(fs_win, "some dir with spaces/calc.exe", None))

    assert target_win.resolve('"\\??\\C:\\windows\\system32\\calc.exe" -args') == "C:/windows/system32/calc.exe"
    assert target_win.resolve("C:/windows/system32/calc.exe -args") == "C:/windows/system32/calc.exe"
    assert target_win.resolve("C:/some dir with spaces/calc.exe") == "C:/some dir with spaces/calc.exe"
    assert target_win.resolve("C:/some dir with spaces/calc.exe -with -arguments") == "C:/some dir with spaces/calc.exe"

    env_plugin = next(plugin for plugin in target_win._plugins if type(plugin).__name__ == "EnvironmentVariablePlugin")
    env_plugin._pathext = set([".exe", ".bat"])

    assert target_win.resolve("C:/windows/system32/calc -args") == "C:/windows/system32/calc.exe"
    assert target_win.resolve("calc -args") == "sysvol/windows/system32/calc.exe"
