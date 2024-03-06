from typing import Iterator
from unittest.mock import patch

import pytest
from _pytest.fixtures import FixtureRequest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.windows.registry import RegistryPlugin
from dissect.target.tools.reg import main as target_reg
from tests._utils import absolute_path


@pytest.fixture
def target_win_reg(target_win: Target, fs_win: VirtualFilesystem) -> Iterator[Target]:
    fs_win.map_file("Windows/System32/config/SYSTEM", absolute_path("_data/tools/reg/SYSTEM.gz"), "gzip")
    target_win.apply()
    target_win.add_plugin(RegistryPlugin)
    yield target_win


@pytest.mark.parametrize(
    "provided_target, provided_key, arg_depth, arg_length, expected_output",
    [
        # test invalid target
        ("target_default", "FOOBAR", 1, 100, "has no Windows Registry"),
        # test invalid key feedback
        ("target_win_reg", "FOOBAR", 1, 100, "Key 'FOOBAR' does not exist"),
        (
            "target_win_reg",
            "HKEY_LOCAL_MACHINE\\FOOBAR",
            1,
            100,
            "Key 'HKEY_LOCAL_MACHINE\\\\FOOBAR' does not exist",
        ),
        # test key value abbrevation
        (
            "target_win_reg",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\ComputerName",
            1,
            100,
            "- 'ComputerName' 'DESKTOP-M3OSHQU'",
        ),
        (
            "target_win_reg",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\ComputerName",
            1,
            10,
            "- 'ComputerName' 'DESKTOP-M...",
        ),
        # test class name printing
        (
            "target_win_reg",
            "HKLM\\SYSTEM\\ControlSet001\\Control\\Lsa\\Data",
            1,
            100,
            "+ 'Data' (2022-06-23 01:25:23.729778+00:00) (a282942c)",
        ),
    ],
)
def test_reg_output(
    provided_target: Target,
    provided_key: str,
    expected_output: str,
    arg_depth: int,
    arg_length: int,
    capsys: pytest.CaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    request: FixtureRequest,
) -> None:
    provided_target = request.getfixturevalue(provided_target)
    with patch("dissect.target.Target.open_all", return_value=[provided_target]):
        with monkeypatch.context() as m:
            m.setattr(
                "sys.argv",
                ["target-reg", "foo", "--depth", str(arg_depth), "--length", str(arg_length), "--key", provided_key],
            )
            target_reg()
            out, err = capsys.readouterr()
            print(out, err)
            assert expected_output in out or expected_output in err
