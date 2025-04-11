from __future__ import annotations

import argparse
from unittest.mock import patch

from dissect.target.plugin import PluginRegistry
from dissect.target.tools import build_pluginlist


def test_main_output() -> None:
    with (
        patch("argparse.ArgumentParser.parse_args", return_value=argparse.Namespace(verbose=0)),
        patch("dissect.target.tools.build_pluginlist.plugin.generate", return_value=PluginRegistry()),
        patch("builtins.print") as mock_print,
    ):
        build_pluginlist.main()

    expected_output = """
from dissect.target.plugin import (
    FailureDescriptor,
    FunctionDescriptor,
    FunctionDescriptorLookup,
    PluginDescriptor,
    PluginDescriptorLookup,
    PluginRegistry,
)

PLUGINS = PluginRegistry(__plugins__=PluginDescriptorLookup(__regular__={}, __os__={}, __child__={}), __functions__=FunctionDescriptorLookup(__regular__={}, __os__={}, __child__={}), __ostree__={}, __failed__=[])
"""  # noqa: E501

    mock_print.assert_called_with(expected_output)
