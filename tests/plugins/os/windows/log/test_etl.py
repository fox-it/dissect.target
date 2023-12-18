from unittest.mock import patch

import pytest

from dissect.target.plugins.os.windows.log.etl import EtlPlugin


@pytest.fixture
def etl_plugin(target_win):
    return EtlPlugin(target_win)


def test_etl_plugin_shutdown(etl_plugin):
    with patch.object(etl_plugin, "read_etl_files", autospec=True):
        list(etl_plugin.shutdown())
        etl_plugin.read_etl_files.assert_called_with(etl_plugin.PATHS["shutdown"])


def test_etl_plugin_boot(etl_plugin):
    with patch.object(etl_plugin, "read_etl_files", autospec=True):
        list(etl_plugin.boot())
        etl_plugin.read_etl_files.assert_called_with(etl_plugin.PATHS["boot"])
