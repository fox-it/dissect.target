from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.keyboard_layout import KeyboardLayoutPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "com.apple.HIToolbox.plist",
    ],
)
def test_keyboard_layout(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/{test_file}")
    fs_unix.map_file(f"/Library/Preferences/{test_file}", data_file)

    target_unix.add_plugin(KeyboardLayoutPlugin)

    results = list(target_unix.keyboard_layout())
    assert len(results) == 2

    assert results[0].input_source_kind == "Keyboard Layout"
    assert results[0].keyboard_layout_name == "U.S."
    assert results[0].keyboard_layout_id == 0
    assert results[0].enabled_layout
    assert results[0].selected_layout
    assert not results[0].current_layout
    assert results[0].source == "/Library/Preferences/com.apple.HIToolbox.plist"

    assert results[1].input_source_kind == "Keyboard Layout"
    assert results[1].keyboard_layout_name == "Dutch"
    assert results[1].keyboard_layout_id == 26
    assert results[1].enabled_layout
    assert not results[1].selected_layout
    assert not results[1].current_layout
    assert results[1].source == "/Library/Preferences/com.apple.HIToolbox.plist"
