from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.windows.log.etl import EtlPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


@pytest.fixture
def etl_plugin(target_win: Target) -> EtlPlugin:
    return EtlPlugin(target_win)


def test_etl_plugin_shutdown(etl_plugin: EtlPlugin) -> None:
    with patch.object(etl_plugin, "read_etl_files", autospec=True):
        list(etl_plugin.shutdown())
        etl_plugin.read_etl_files.assert_called_with(etl_plugin.PATHS["shutdown"])


def test_etl_plugin_boot(etl_plugin: EtlPlugin) -> None:
    with patch.object(etl_plugin, "read_etl_files", autospec=True):
        list(etl_plugin.boot())
        etl_plugin.read_etl_files.assert_called_with(etl_plugin.PATHS["boot"])
