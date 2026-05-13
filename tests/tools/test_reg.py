from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.windows.registry import RegistryPlugin
from dissect.target.tools.reg import main as target_reg
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    from _pytest.fixtures import FixtureRequest

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_win_reg(target_win: Target, fs_win: VirtualFilesystem) -> Target:
    fs_win.map_file("Windows/System32/config/SYSTEM", absolute_path("_data/tools/reg/SYSTEM.gz"), "gzip")
    target_win.apply()
    target_win.add_plugin(RegistryPlugin)
    return target_win


@pytest.mark.parametrize(
    ("provided_target", "provided_key", "arg_depth", "arg_length", "expected_output", "expected_log"),
    [
        # test invalid target
        ("target_default", "FOOBAR", 1, 100, "", "has no Windows Registry"),
        # test invalid key feedback
        ("target_win_reg", "FOOBAR", 1, 100, "", "Key 'FOOBAR' does not exist"),
        (
            "target_win_reg",
            "HKEY_LOCAL_MACHINE\\FOOBAR",
            1,
            100,
            "",
            "Key 'HKEY_LOCAL_MACHINE\\\\FOOBAR' does not exist",
        ),
        # test key value abbrevation
        (
            "target_win_reg",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\ComputerName",
            1,
            100,
            "- 'ComputerName' 'DESKTOP-M3OSHQU'",
            "",
        ),
        (
            "target_win_reg",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\ComputerName",
            1,
            10,
            "- 'ComputerName' 'DESKTOP-M...",
            "",
        ),
        # test class name printing
        (
            "target_win_reg",
            "HKLM\\SYSTEM\\ControlSet001\\Control\\Lsa\\Data",
            1,
            100,
            "+ 'Data' (2022-06-23 01:25:23.729778+00:00) (a282942c)",
            "",
        ),
    ],
)
def test_reg_output(
    provided_target: Target,
    provided_key: str,
    expected_output: str,
    expected_log: str,
    arg_depth: int,
    arg_length: int,
    capsys: pytest.CaptureFixture,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    request: FixtureRequest,
) -> None:
    provided_target = request.getfixturevalue(provided_target)
    with patch("dissect.target.Target.open_all", return_value=[provided_target]), monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            ["target-reg", "foo", "--depth", str(arg_depth), "--length", str(arg_length), "--key", provided_key],
        )
        target_reg()
        out, err = capsys.readouterr()
        print(out, err)
        assert expected_output in out or expected_output in err
        assert expected_log in caplog.text


def test_reg_export_to_stdout(
    target_win_reg: Target,
    capsys: pytest.CaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--export writes a valid .reg file to stdout for the requested key."""
    key = "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\ComputerName"
    with patch("dissect.target.Target.open_all", return_value=[target_win_reg]), monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-reg", "foo", "--export", "--key", key])
        target_reg()

    out, _ = capsys.readouterr()
    assert out.startswith("Windows Registry Editor Version 5.00")
    assert f";   {key}" in out
    assert f"[{key}]" in out
    assert '"ComputerName"=' in out


def test_reg_export_multiple_keys(
    target_win_reg: Target,
    capsys: pytest.CaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple -k flags each appear as path comments and key headers in the export."""
    key1 = "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\ComputerName"
    key2 = "HKLM\\SYSTEM\\ControlSet001\\Control\\Lsa\\Data"
    with patch("dissect.target.Target.open_all", return_value=[target_win_reg]), monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-reg", "foo", "--export", "--key", key1, "--key", key2])
        target_reg()

    out, _ = capsys.readouterr()
    assert f";   {key1}" in out
    # key2 shortname should be expanded in the comment
    assert ";   HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Lsa\\Data" in out
    assert f"[{key1}]" in out
    assert "[HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Lsa\\Data]" in out


def test_reg_export_to_file(
    target_win_reg: Target,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--export --output writes the .reg file to the given path."""
    key = "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\ComputerName"
    output_file = tmp_path / "export.reg"
    with patch("dissect.target.Target.open_all", return_value=[target_win_reg]), monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-reg", "foo", "--export", "--key", key, "--output", str(output_file)])
        target_reg()

    content = output_file.read_text(encoding="utf-8")
    assert content.startswith("Windows Registry Editor Version 5.00")
    assert f"[{key}]" in content
    assert '"ComputerName"=' in content


def test_reg_export_missing_key(
    target_win_reg: Target,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--export logs an error for a key that does not exist and continues."""
    with patch("dissect.target.Target.open_all", return_value=[target_win_reg]), monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-reg", "foo", "--export", "--key", "HKEY_LOCAL_MACHINE\\DOESNOTEXIST"])
        target_reg()

    assert "does not exist" in caplog.text
