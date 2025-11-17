import io
import pytest
from unittest.mock import MagicMock, mock_open, patch
from datetime import datetime, timezone
import logging

from dissect.target.plugins.os.windows.log.intunemanagementextension import (
    IntuneManagementExtensionLogParserPlugin,
    IntuneManagementExtensionLogRecord,
)
from dissect.target.exceptions import UnsupportedPluginError

@pytest.fixture
def fake_target():
    """Create a fake target object with a mocked filesystem."""
    target = MagicMock()
    fs = MagicMock()
    target.fs = fs
    target.hostname = MagicMock(return_value="mock_hostname")
    target.domain = MagicMock(return_value="mock_domain")
    return target

def create_mock_file(name: str, content: str):
    mock = MagicMock()
    mock.name = name
    mock.open = mock_open(read_data=content)
    return mock

def test_check_compatible_pass(fake_target):
    """Should not raise if log directory and log files exist."""
    fake_dir = MagicMock()
    fake_file = create_mock_file("IntuneManagementExtension.log", "dummy content")
    fake_dir.exists.return_value = True
    fake_dir.iterdir.return_value = [fake_file]
    fake_target.fs.path.return_value = fake_dir
    plugin = IntuneManagementExtensionLogParserPlugin(fake_target)
    plugin.check_compatible()

def test_check_compatible_missing_dir(fake_target):
    """Should raise if log directory does not exist."""
    fake_dir = MagicMock()
    fake_dir.exists.return_value = False
    fake_target.fs.path.return_value = fake_dir
    plugin = IntuneManagementExtensionLogParserPlugin(fake_target)
    with pytest.raises(UnsupportedPluginError, match="log directory not found"):
        plugin.check_compatible()

def test_check_compatible_no_logs(fake_target):
    """Should raise if directory exists but no log files are found."""
    fake_dir = MagicMock()
    fake_dir.exists.return_value = True
    fake_dir.iterdir.return_value = [create_mock_file("not_a_log.txt", "")]
    fake_target.fs.path.return_value = fake_dir
    plugin = IntuneManagementExtensionLogParserPlugin(fake_target)
    with pytest.raises(UnsupportedPluginError, match="No Intune Management Extension logs found"):
        plugin.check_compatible()

def test_intunemanagementextension_yields_valid_records(fake_target):
    """Should correctly parse log entries and yield structured records."""
    log_content = """<![LOG[Test message one with
multi-line content.]LOG]!><time="10:13:29.9211136" date="12-2-2024"
    component="IntuneManagementExtension" context="ManagedSoftware" type="1" thread="1001" file="">
<![LOG[Another entry, testing DD-MM-YYYY format and internal file origin.]LOG]!><time="11:00:00.000000" date="02-12-2024"
    component="IntuneManagementExtensionService" context="Agent" type="2" thread="1002" file="SomeModule.cpp">
<![LOG[YYYY-MM-DD format test.]LOG]!><time="12:30:00.000000" date="2024-03-15"
    component="IntuneManagementExtension" context="Policy" type="3" thread="1003" file="">
"""
    fake_file = create_mock_file("IntuneManagementExtension.log", log_content)
    fake_dir = MagicMock()
    fake_dir.iterdir.return_value = [fake_file]
    fake_dir.exists.return_value = True
    fake_target.fs.path.return_value = fake_dir

    plugin = IntuneManagementExtensionLogParserPlugin(fake_target)
    records = list(plugin.intunemanagementextension())

    assert len(records) == 3
    rec1, rec2, rec3 = records

    expected_dt1 = datetime(2024, 12, 2, 10, 13, 29, 921113, tzinfo=timezone.utc)
    expected_dt2 = datetime(2024, 2, 12, 11, 0, 0, 0, tzinfo=timezone.utc)
    expected_dt3 = datetime(2024, 3, 15, 12, 30, 0, 0, tzinfo=timezone.utc)

    assert type(rec1).__name__ == "IntuneManagementExtension_log"
    assert rec1.timestamp == expected_dt1
    assert rec1.component == "IntuneManagementExtension"
    assert rec1.thread == "1001"
    assert rec1.type == "1"

    assert "Test message one with multi-line content." in rec1.message
    assert rec1.file_origin == "IntuneManagementExtension.log:"

    assert type(rec2).__name__ == "IntuneManagementExtension_log"
    assert rec2.timestamp == expected_dt2
    assert rec2.component == "IntuneManagementExtensionService"
    assert rec2.thread == "1002"
    assert rec2.type == "2"
    
    assert "Another entry, testing DD-MM-YYYY format and internal file origin." in rec2.message
    assert rec2.file_origin == "IntuneManagementExtension.log:SomeModule.cpp" 

    assert type(rec3).__name__ == "IntuneManagementExtension_log"
    assert rec3.timestamp == expected_dt3
    assert rec3.component == "IntuneManagementExtension"
    assert rec3.thread == "1003"
    assert rec3.type == "3"
    assert "YYYY-MM-DD format test." in rec3.message
    assert rec3.file_origin == "IntuneManagementExtension.log:"


def test_intunemanagementextension_handles_empty_file(fake_target):
    """Should handle empty files gracefully."""
    fake_file = create_mock_file("IntuneManagementExtension.log", "")
    fake_dir = MagicMock()
    fake_dir.iterdir.return_value = [fake_file]
    fake_dir.exists.return_value = True
    fake_target.fs.path.return_value = fake_dir
    plugin = IntuneManagementExtensionLogParserPlugin(fake_target)
    records = list(plugin.intunemanagementextension())
    assert records == []

def test_intunemanagementextension_skips_unparseable_timestamp(fake_target, caplog):
    """Should skip entries that don't match the regex pattern and log a warning."""
    log_content = """<![LOG[Bad date entry]LOG]!><time="10:00:00" date="bad-date"
    component="IntuneManagementExtension" context="" type="1" thread="1" file="">
"""
    fake_file = create_mock_file("IntuneManagementExtension.log", log_content)
    fake_dir = MagicMock()
    fake_dir.iterdir.return_value = [fake_file]
    fake_dir.exists.return_value = True
    fake_target.fs.path.return_value = fake_dir
    plugin = IntuneManagementExtensionLogParserPlugin(fake_target)
    
    with caplog.at_level(logging.WARNING):
        records = list(plugin.intunemanagementextension())
    
    assert len(records) == 0 
    assert any("No log entries matched regex in" in record.message for record in caplog.records if record.levelno == logging.WARNING)


def test_intunemanagementextension_warns_on_no_matches_in_file(fake_target, caplog):
    """Should log a warning if a log file contains no regex matches."""
    fake_file = create_mock_file("IntuneManagementExtension.log", "This file contains no valid log entries.")
    fake_dir = MagicMock()
    fake_dir.iterdir.return_value = [fake_file]
    fake_dir.exists.return_value = True
    fake_target.fs.path.return_value = fake_dir
    plugin = IntuneManagementExtensionLogParserPlugin(fake_target)
    with caplog.at_level(logging.WARNING):
        list(plugin.intunemanagementextension())
    assert any("No log entries matched regex in" in record.message for record in caplog.records)


def test_intunemanagementextension_handles_rotated_logs(fake_target):
    """Should parse records from multiple rotated log files."""
    log_content_main = """<![LOG[Main log entry]LOG]!><time="09:00:00.000000" date="1-1-2024"
    component="Main" context="MainContext" type="1" thread="1" file="">
"""
    log_content_rotated = """<![LOG[Rotated log entry]LOG]!><time="10:00:00.000000" date="1-1-2023"
    component="Rotated" context="RotatedContext" type="1" thread="1" file="">
"""
    fake_file_main = create_mock_file("IntuneManagementExtension.log", log_content_main)
    fake_file_rotated = create_mock_file("IntuneManagementExtension-20230101-100000.log", log_content_rotated)
    
    fake_dir = MagicMock()
    fake_dir.iterdir.return_value = [fake_file_main, fake_file_rotated]
    fake_dir.exists.return_value = True
    fake_target.fs.path.return_value = fake_dir

    plugin = IntuneManagementExtensionLogParserPlugin(fake_target)
    records = list(plugin.intunemanagementextension())

    assert len(records) == 2
    
    records.sort(key=lambda r: r.timestamp)

    assert records[0].component == "Rotated"
    assert records[0].timestamp == datetime(2023, 1, 1, 10, 0, 0, 0, tzinfo=timezone.utc)
    assert records[0].file_origin == "IntuneManagementExtension-20230101-100000.log:" 
    assert records[1].component == "Main"
    assert records[1].timestamp == datetime(2024, 1, 1, 9, 0, 0, 0, tzinfo=timezone.utc)
    assert records[1].file_origin == "IntuneManagementExtension.log:"


def test_intunemanagementextension_file_open_failure(fake_target, caplog):
    """Should handle file open errors gracefully for individual files."""
    good_log_content = """<![LOG[Good entry]LOG]!><time="09:00:00.000000" date="1-1-2024"
    component="Good" context="FileOpenSuccess" type="1" thread="1" file="">
"""
    fake_file_good = create_mock_file("IntuneManagementExtension.log", good_log_content)
    fake_file_bad = MagicMock()
    fake_file_bad.name = "IntuneManagementExtension-bad.log"
    fake_file_bad.open.side_effect = IOError("Permission denied to file_bad")
    
    fake_dir = MagicMock()
    fake_dir.iterdir.return_value = [fake_file_good, fake_file_bad]
    fake_dir.exists.return_value = True
    fake_target.fs.path.return_value = fake_dir

    plugin = IntuneManagementExtensionLogParserPlugin(fake_target)
    with caplog.at_level(logging.ERROR): 
        records = list(plugin.intunemanagementextension())

    assert len(records) == 1 
    assert records[0].component == "Good"
    assert any("Failed to open log file" in record.message for record in caplog.records)
    assert any("Permission denied to file_bad" in record.message for record in caplog.records)
