from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows.dpapi.dpapi import DPAPIPlugin
from dissect.target.plugins.os.windows.dpapi.keyprovider.empty import EmptyKeyProviderPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_dpapi_keyprovider_empty(target_win: Target) -> None:
    """test if we yield an empty key correctly."""

    target_win.add_plugin(DPAPIPlugin, check_compatible=False)
    target_win.add_plugin(EmptyKeyProviderPlugin)

    key = next(target_win.dpapi.keyprovider.empty())

    assert key == ("dpapi.keyprovider.empty", "")
