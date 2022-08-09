from unittest.mock import patch, mock_open, MagicMock

from dissect.target.containers.raw import RawContainer
from dissect.target.loaders.local import _add_disk_as_raw_container_to_target
from dissect.target.target import TargetLogAdapter


def test_local_loader_drive_skipping(mock_target):
    mock = mock_open()
    # Does it attempt to open the file and pass a raw container?
    with patch("builtins.open", mock):
        with patch.object(mock_target.disks, "add") as mock_method:
            drive = "/xdev/fake"
            _add_disk_as_raw_container_to_target(drive, mock_target)
            assert isinstance(mock_method.call_args[0][0], RawContainer) == True
    mock.assert_called_with("/xdev/fake", "rb")

    # Does it emit a warning instead of raising an exception?
    mock.side_effect = IOError
    with patch.object(TargetLogAdapter, "warning") as mock_method:
        with patch("builtins.open", mock):
            drive = "/xdev/fake"
            _add_disk_as_raw_container_to_target(drive, mock_target)
        mock_method.assert_called_with("Unable to open drive: /xdev/fake, skipped")
    mock.assert_called_with("/xdev/fake", "rb")
