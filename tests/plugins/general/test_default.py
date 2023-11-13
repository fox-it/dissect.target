from typing import Union

import pytest

from dissect.target.plugins.general.default import DefaultPlugin
from dissect.target.target import Target


@pytest.mark.parametrize(
    "method_name, result",
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
    result: Union[None, str, list],
) -> str:
    os_plugin = DefaultPlugin(target_default)
    attr = getattr(os_plugin, method_name)
    assert attr == result
