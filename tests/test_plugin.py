import os
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from dissect.target.plugin import (
    environment_variable_paths,
    load_external_module_paths,
    save_plugin_import_failure,
)


def test_save_plugin_import_failure():
    test_trace = ["test-trace"]
    test_module_name = "test-module"

    with patch("traceback.format_exception", Mock(return_value=test_trace)):
        with patch("dissect.target.plugin.PLUGINS", new_callable=dict) as MOCK_PLUGINS:
            MOCK_PLUGINS["_failed"] = []
            save_plugin_import_failure(test_module_name)

            assert len(MOCK_PLUGINS["_failed"]) == 1
            assert MOCK_PLUGINS["_failed"][0].get("module") == test_module_name
            assert MOCK_PLUGINS["_failed"][0].get("stacktrace") == test_trace


@pytest.mark.parametrize(
    "env_value, expected_output",
    [
        (None, []),
        ("", []),
        (":", [Path(""), Path("")]),
    ],
)
def test_load_environment_variable(env_value, expected_output):
    with patch.object(os, "environ", {"DISSECT_PLUGINS": env_value}):
        assert environment_variable_paths() == expected_output


def test_load_module_paths():
    assert load_external_module_paths([Path(""), Path("")]) == [Path("")]


def test_load_paths_with_env():
    with patch.object(os, "environ", {"DISSECT_PLUGINS": ":"}):
        assert load_external_module_paths([Path(""), Path("")]) == [Path("")]
