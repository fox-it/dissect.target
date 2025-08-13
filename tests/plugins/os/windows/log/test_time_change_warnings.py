import pytest
from unittest.mock import Mock

from dissect.target.plugins.os.windows.log import evtx, evt
from dissect.target.target import Target
from tests._utils import absolute_path


def test_evtx_time_change_warning_detection():
    """Test that EVTX plugin detects time change events correctly."""
    
    target = Target()
    plugin = evtx.EvtxPlugin(target)
    
    # Test cases for time change event detection
    assert plugin._is_time_change_event(1, "Microsoft-Windows-Kernel-General") is True
    assert plugin._is_time_change_event(4616, "Microsoft-Windows-Security-Auditing") is True
    assert plugin._is_time_change_event(1, "SomeOtherProvider") is False
    assert plugin._is_time_change_event(4616, "SomeOtherProvider") is False
    assert plugin._is_time_change_event(1234, "Microsoft-Windows-Kernel-General") is False
    assert plugin._is_time_change_event(None, "Microsoft-Windows-Kernel-General") is False


def test_evt_time_change_warning_detection():
    """Test that EVT plugin detects time change events correctly."""
    
    target = Target()
    plugin = evt.EvtPlugin(target)
    
    # Test cases for time change event detection
    assert plugin._is_time_change_event(1, "Microsoft-Windows-Kernel-General") is True
    assert plugin._is_time_change_event(4616, "Microsoft-Windows-Security-Auditing") is True
    assert plugin._is_time_change_event(1, "SomeOtherProvider") is False
    assert plugin._is_time_change_event(4616, "SomeOtherProvider") is False
    assert plugin._is_time_change_event(1234, "Microsoft-Windows-Kernel-General") is False
    assert plugin._is_time_change_event(None, "Microsoft-Windows-Kernel-General") is False


def test_evtx_time_change_warning_logged():
    """Test that time change events trigger warning logs in EVTX plugin."""
    
    # Create a mock EVTX record that represents a time change event
    mock_record = {
        "EventID": 4616,
        "Provider_Name": "Microsoft-Windows-Security-Auditing",
        "TimeCreated_SystemTime": "2023-01-01T00:00:00Z"
    }
    
    target = Target()
    
    # Mock the target's log warning method
    original_warning = target.log.warning
    warning_calls = []
    def mock_warning(*args, **kwargs):
        warning_calls.append((args, kwargs))
        return original_warning(*args, **kwargs)
    
    target.log.warning = mock_warning
    plugin = evtx.EvtxPlugin(target)
    
    # Process the record - this should trigger a warning
    result = plugin._build_record(mock_record, None)
    
    # Verify warning was called
    assert len(warning_calls) == 1
    args = warning_calls[0][0]
    assert "Time change event detected" in args[0]
    assert "4616" in str(args[1])
    assert "Microsoft-Windows-Security-Auditing" in str(args[2])


def test_evt_time_change_warning_logged():  
    """Test that time change events trigger warning logs in EVT plugin."""
    
    # Create a mock EVT record that represents a time change event
    mock_record = Mock()
    mock_record.EventID = 1
    mock_record.SourceName = "Microsoft-Windows-Kernel-General"
    mock_record.TimeGenerated = "2023-01-01T00:00:00Z"
    mock_record.TimeWritten = "2023-01-01T00:00:00Z"
    mock_record.EventCode = 1
    mock_record.EventFacility = 0
    mock_record.EventCustomerFlag = 0
    mock_record.EventSeverity = 0
    mock_record.EventType = 0
    mock_record.EventCategory = 0
    mock_record.Computername = "TestComputer"
    mock_record.Strings = []
    mock_record.Data = b""
    
    target = Target()
    
    # Mock the target's log warning method
    original_warning = target.log.warning
    warning_calls = []
    def mock_warning(*args, **kwargs):
        warning_calls.append((args, kwargs))
        return original_warning(*args, **kwargs)
    
    target.log.warning = mock_warning
    plugin = evt.EvtPlugin(target)
    
    # Process the record - this should trigger a warning
    result = plugin._build_record(mock_record)
    
    # Verify warning was called
    assert len(warning_calls) == 1
    args = warning_calls[0][0]
    assert "Time change event detected" in args[0]
    assert "1" in str(args[1])
    assert "Microsoft-Windows-Kernel-General" in str(args[2])


def test_evtx_with_security_log_produces_warning():
    """Integration test to verify warning is produced when processing Security.evtx."""
    
    import logging
    from io import StringIO
    
    # Set up a string stream to capture log output
    log_capture_string = StringIO()
    ch = logging.StreamHandler(log_capture_string)
    ch.setLevel(logging.WARNING)
    
    # Add the handler to the dissect.target logger
    logger = logging.getLogger("dissect.target")
    original_level = logger.level
    logger.setLevel(logging.WARNING)
    logger.addHandler(ch)
    
    try:
        evtx_file = absolute_path("_data/plugins/os/windows/log/evtx/Security.evtx")
        target = Target.open_direct([evtx_file])
        plugin = evtx.EvtxPlugin(target)
        
        # Process some records to find the time change event
        count = 0
        found_time_change_event = False
        for record in plugin.evtx():
            count += 1
            if hasattr(record, 'EventID') and record.EventID == 4616:
                # Found the time change event
                found_time_change_event = True
                break
            if count > 300:  # Safety limit
                break
        
        # Check if we found the time change event
        assert found_time_change_event, "Expected to find Event ID 4616 in Security.evtx"
        
        # Check the captured log output
        log_contents = log_capture_string.getvalue()
        assert "time change" in log_contents.lower(), f"Expected time change warning in logs, got: {log_contents}"
        
    finally:
        # Clean up logging
        logger.removeHandler(ch)
        logger.setLevel(original_level)
        ch.close()