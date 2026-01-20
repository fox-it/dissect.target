from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugins.os.windows.log.agentexecutor import AgentExecutorLogPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


LOG_PATH = "ProgramData/Microsoft/IntuneManagementExtension/Logs/AgentExecutor.log"


def test_agentexecutor_check_compatible_missing_file(target_win: Target) -> None:
    """Plugin should raise if the AgentExecutor log is missing."""
    with pytest.raises(UnsupportedPluginError):
        target_win.add_plugin(AgentExecutorLogPlugin)


def test_agentexecutor_check_compatible_success(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Plugin should load when the AgentExecutor log exists."""
    fs_win.map_file(
        LOG_PATH,
        absolute_path("_data/plugins/os/windows/log/agentexecutor/agentexecutor.log"),
    )

    target_win.add_plugin(AgentExecutorLogPlugin)


def test_agentexecutor_parsing_valid_entries(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Should parse valid AgentExecutor log entries."""
    fs_win.map_file(
        LOG_PATH,
        absolute_path("_data/plugins/os/windows/log/agentexecutor/agentexecutor.log"),
    )

    target_win.add_plugin(AgentExecutorLogPlugin)
    records = list(target_win.agentexecutor())

    assert len(records) == 2

    first, second = records

    assert type(first).__name__ == "windows_intune_agentexecutor_log"
    assert first.component == "AgentExecutor"
    assert first.thread == "1"
    assert first.type == "1"
    assert first.context == ""
    assert "DNS detection failed with multi-line" in first.message
    assert first.file_origin == "AgentExecutor.log"

    assert type(second).__name__ == "windows_intune_agentexecutor_log"
    assert second.component == "AgentExecutorService"
    assert second.thread == "2"
    assert second.type == "2"
    assert second.context == "CTX"
    assert "Another entry, testing DD-MM-YYYY format" in second.message
    assert second.file_origin == "ExplicitLogFile.log"
