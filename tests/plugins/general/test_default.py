from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.default._os import DefaultOSPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("method_name", "result"),
    [
        ("hostname", None),
        ("ips", []),
        ("version", None),
        ("os", "default"),
        ("architecture", None),
    ],
)
def test_default_plugin_property_methods(
    target_default: Target,
    method_name: str,
    result: None | str | list,
) -> str:
    os_plugin = DefaultOSPlugin(target_default)
    attr = getattr(os_plugin, method_name)
    assert attr == result
