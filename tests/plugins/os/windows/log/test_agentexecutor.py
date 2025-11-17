import pytest
from unittest.mock import MagicMock, mock_open
from datetime import datetime, timezone
from dissect.target.plugins.os.windows.log.agentexecutor import (
    AgentExecutorLogPlugin,
    AgentExecutorLogRecord,
)
from dissect.target.exceptions import UnsupportedPluginError

@pytest.fixture
def fake_target():
    """Create a mock target with a fake filesystem."""
    target = MagicMock()
    target.fs = MagicMock()
    return target

def test_check_compatible_success(fake_target):
    """Should pass if the AgentExecutor log file exists."""
    fake_file = MagicMock()
    fake_file.exists.return_value = True
    fake_target.fs.path.return_value = fake_file
    plugin = AgentExecutorLogPlugin(fake_target)
    plugin.check_compatible()

def test_check_compatible_missing_file(fake_target):
    """Should raise if the AgentExecutor log file is missing."""
    fake_file = MagicMock()
    fake_file.exists.return_value = False
    fake_target.fs.path.return_value = fake_file
    plugin = AgentExecutorLogPlugin(fake_target)
    with pytest.raises(UnsupportedPluginError):
        plugin.check_compatible()

def test_agentexecutor_parsing_valid_entries(fake_target):
    """Should correctly parse valid log entries, including timestamps and defaults."""
    log_content = """<![LOG[DNS detection failed with multi-line
message.
Some more details here.]LOG]!><time="10:13:29.9211136" date="12-2-2024"
component="AgentExecutor" context="" type="1" thread="1" file="">
<![LOG[Another entry, testing DD-MM-YYYY format and specific file.]LOG]!><time="11:00:00.000000" date="02-12-2024"
component="AgentExecutorService" context="CTX" type="2" thread="2" file="ExplicitLogFile.log">
"""
    fake_file = MagicMock()
    fake_file.exists.return_value = True
    fake_file.open = mock_open(read_data=log_content)
    fake_target.fs.path.return_value = fake_file
    plugin = AgentExecutorLogPlugin(fake_target)
    records = list(plugin.agentexecutor())

    assert len(records) == 2
    first, second = records

    expected_first_dt = datetime(2024, 12, 2, 10, 13, 29, 921113, tzinfo=timezone.utc)
    expected_second_dt = datetime(2024, 2, 12, 11, 0, 0, 0, tzinfo=timezone.utc)

    assert type(first).__name__ == "agentexecutor_log"
    assert first.component == "AgentExecutor"
    assert first.thread == "1"
    assert first.type == "1"
    assert first.context == ""
    assert "DNS detection failed with multi-line\nmessage.\nSome more details here." in first.message
    assert first.file_origin == "AgentExecutor.log"
    assert first.timestamp == expected_first_dt

    assert type(second).__name__ == "agentexecutor_log"
    assert second.component == "AgentExecutorService"
    assert second.thread == "2"
    assert second.type == "2"
    assert second.context == "CTX"
    assert "Another entry, testing DD-MM-YYYY format and specific file." in second.message
    assert second.file_origin == "ExplicitLogFile.log"
    assert second.timestamp == expected_second_dt

def test_agentexecutor_handles_empty_file(fake_target):
    """Should handle empty file gracefully."""
    fake_file = MagicMock()
    fake_file.exists.return_value = True
    fake_file.open = mock_open(read_data="")
    fake_target.fs.path.return_value = fake_file
    plugin = AgentExecutorLogPlugin(fake_target)
    records = list(plugin.agentexecutor())
    assert records == []

def test_agentexecutor_skips_bad_timestamps(fake_target):
    """Should skip entries with malformed date/time."""
    log_content = """<![LOG[Bad timestamp]LOG]!><time="xx:yy:zz" date="not-a-date"
component="AgentExecutor" context="" type="1" thread="1" file="">
"""
    fake_file = MagicMock()
    fake_file.exists.return_value = True
    fake_file.open = mock_open(read_data=log_content)
    fake_target.fs.path.return_value = fake_file
    plugin = AgentExecutorLogPlugin(fake_target)
    records = list(plugin.agentexecutor())
    assert len(records) == 0

def test_agentexecutor_warns_on_no_matches(fake_target, caplog):
    """Should log a warning if no regex matches occur."""
    fake_file = MagicMock()
    fake_file.exists.return_value = True
    fake_file.open = mock_open(read_data="This does not match anything")
    fake_target.fs.path.return_value = fake_file
    plugin = AgentExecutorLogPlugin(fake_target)
   
    with caplog.at_level('WARNING'):
        list(plugin.agentexecutor())
    assert any("No log entries matched the regex" in record.message for record in caplog.records)

def test_agentexecutor_file_open_failure(fake_target, caplog):
    """Should handle file open errors gracefully."""
    fake_file = MagicMock()
    fake_file.exists.return_value = True
    fake_file.open.side_effect = IOError("Permission denied")
    fake_target.fs.path.return_value = fake_file

    plugin = AgentExecutorLogPlugin(fake_target)
    with caplog.at_level('ERROR'):
        records = list(plugin.agentexecutor())

    assert records == []
    assert any("Failed to open log file" in record.message for record in caplog.records)
