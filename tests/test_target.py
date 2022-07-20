import urllib.parse

import pytest
from unittest.mock import MagicMock, Mock, PropertyMock, call, patch

from dissect.target.target import Event, Target
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.exceptions import FilesystemError


@pytest.fixture
def mocked_win_volumes_fs():
    mock_bad_volume = Mock(name="bad-volume-Z")
    mock_bad_volume.fs = None
    mock_bad_volume.drive_letter = "Z"

    mock_good_volume = Mock(name="good-volume-W")
    mock_good_volume.fs = None
    mock_good_volume.drive_letter = "W"

    mock_good_fs = Mock(name="good-fs")

    def mock_filesystem_open(volume):
        if volume == mock_good_volume:
            return mock_good_fs
        raise FilesystemError("Not supported")

    def get_mock_drive_volumes(_):
        # drive_volume, is_windrive, disk, disk_num
        return [
            (mock_good_volume, False, Mock(), 1),
            (mock_bad_volume, False, Mock(), 2),
        ]

    def mock_disk_apply(self):
        if len(self.target.disks) > 0:
            self.target.volumes.add(mock_good_volume)
            self.target.volumes.add(mock_bad_volume)

    with patch("dissect.target.loaders.local._get_os_name") as mock_os_name, patch(
        "dissect.target.filesystem.open", new=mock_filesystem_open
    ), patch("dissect.target.plugin.os_plugins") as mock_os_plugins, patch(
        "dissect.target.target.DiskCollection.apply", new=mock_disk_apply
    ), patch(
        "dissect.target.loaders.local._get_windows_drive_volumes", new=get_mock_drive_volumes
    ):

        mock_os_plugins.return_value = []
        mock_os_name.return_value = "windows"

        yield (mock_good_volume, mock_bad_volume, mock_good_fs)


@pytest.fixture
def mocked_lin_volumes_fs():
    mock_bad_volume = Mock(name="bad-volume")
    mock_bad_volume.fs = None

    mock_good_volume = Mock(name="good-volume")
    mock_good_volume.fs = None

    mock_good_fs = Mock(name="good-fs")

    def mock_filesystem_open(volume):
        if volume == mock_good_volume:
            return mock_good_fs
        raise FilesystemError("Not supported")

    def mock_disk_apply(self):
        if len(self.target.disks) > 0:
            self.target.volumes.add(mock_good_volume)
            self.target.volumes.add(mock_bad_volume)

    with patch("dissect.target.loaders.local._get_os_name") as mock_os_name, patch(
        "dissect.target.filesystem.open", new=mock_filesystem_open
    ), patch("dissect.target.plugin.os_plugins") as mock_os_plugins, patch(
        "dissect.target.target.DiskCollection.apply", new=mock_disk_apply
    ):

        mock_os_plugins.return_value = []
        mock_os_name.return_value = "linux"

        yield (mock_good_volume, mock_bad_volume, mock_good_fs)


def test_target_win_force_dirfs(mocked_win_volumes_fs):

    mock_good_volume, mock_bad_volume, mock_good_fs = mocked_win_volumes_fs

    query = {"force-directory-fs": 1}
    target_query = urllib.parse.urlencode(query)
    force_dirfs_path = f"local?{target_query}"
    target = Target.open(force_dirfs_path)

    assert "force-directory-fs" in target.path_query

    # original volumes are attached
    assert len(target.volumes) == 2

    # FSs from both volumes, bad and good, are mounted + 2 mounts by DefaultPlugin
    assert set(target.fs.mounts.keys()) == {
        mock_bad_volume.drive_letter,
        mock_good_volume.drive_letter,
        "fs0",
        "fs1",
    }

    # both volumes should be mounted as DirectoryFilesystem
    assert isinstance(target.fs.mounts[mock_good_volume.drive_letter], DirectoryFilesystem)
    assert isinstance(target.fs.mounts[mock_bad_volume.drive_letter], DirectoryFilesystem)


def test_target_win_fallback_dirfs(mocked_win_volumes_fs):

    mock_good_volume, mock_bad_volume, mock_good_fs = mocked_win_volumes_fs

    query = {"fallback-to-directory-fs": 1}
    target_query = urllib.parse.urlencode(query)
    fallback_dirfs_path = f"local?{target_query}"
    target = Target.open(fallback_dirfs_path)

    assert "fallback-to-directory-fs" in target.path_query

    # both volumes are present
    assert len(target.volumes) == 2

    # FSs from both volumes, bad and good, are mounted + 2 mounts by DefaultPlugin
    assert set(target.fs.mounts.keys()) == {
        mock_bad_volume.drive_letter,
        mock_good_volume.drive_letter,
        "fs0",
        "fs1",
    }

    # One volume is mounted as DirectoryFilesystem, another as original mock_good_fs
    assert target.fs.mounts[mock_good_volume.drive_letter] == mock_good_fs
    assert isinstance(target.fs.mounts[mock_bad_volume.drive_letter], DirectoryFilesystem)


def test_target_force_dirfs_linux(mocked_lin_volumes_fs):

    mock_good_volume, mock_bad_volume, mock_good_fs = mocked_lin_volumes_fs

    query = {"force-directory-fs": 1}
    target_query = urllib.parse.urlencode(query)
    force_dirfs_path = f"local?{target_query}"
    target = Target.open(force_dirfs_path)

    assert "force-directory-fs" in target.path_query

    # no original volumes should be attached
    assert len(target.volumes) == 0

    assert len(target.fs.mounts) == 1
    assert target.fs.mounts.get("/")
    assert isinstance(target.fs.mounts["/"], DirectoryFilesystem)


def test_target_fallback_dirfs_linux(mocked_lin_volumes_fs):

    mock_good_volume, mock_bad_volume, mock_good_fs = mocked_lin_volumes_fs

    query = {"fallback-to-directory-fs": 1}
    target_query = urllib.parse.urlencode(query)
    fallback_dirfs_path = f"local?{target_query}"
    target = Target.open(fallback_dirfs_path)

    assert "fallback-to-directory-fs" in target.path_query

    # no volumes should be attached, since no disks were attached
    # see comment in LocalLoader.map() for more info
    assert len(target.volumes) == 0

    assert len(target.fs.mounts) == 1
    assert target.fs.mounts.get("/")
    assert isinstance(target.fs.mounts["/"], DirectoryFilesystem)


def test_target__generic_name_no_path_no_os():
    mock_target = Target()

    assert mock_target._generic_name == "Unknown"


def test_target__generic_name_no_path_with_os():
    mock_target = Target()
    mock_target.os = "test"

    assert mock_target._generic_name == "Unknown-test"


def test_target__generic_name_with_path(mock_target):
    assert mock_target._generic_name == mock_target.path.name


def test_target_name_no_hostname():
    test_name = "test-target"

    with patch("dissect.target.target.Target._generic_name", PropertyMock(return_value=test_name)):
        mock_target = Target()
        mock_target.hostname = None

        assert mock_target.name == test_name


def test_target_name_hostname_raises():
    test_name = "test-target"

    with patch("dissect.target.target.Target._generic_name", PropertyMock(return_value=test_name)):
        with patch("dissect.target.target.Target.hostname", PropertyMock(side_effect=Exception("ERROR")), create=True):
            mock_target = Target()

            assert mock_target.name == test_name


def test_target_name_set():
    test_name = "test-target"
    mock_target = Target()
    mock_target._name = test_name

    assert mock_target.name == test_name


def test_target_name_target_applied():
    test_name = "test-target"

    with patch("dissect.target.target.Target._generic_name", PropertyMock(return_value=test_name)):
        mock_target = Target()
        mock_target.hostname = None
        mock_target._applied = True

        assert mock_target.name == test_name
        assert mock_target._name == test_name


def test_target_set_event_callback():
    mock_callback1 = MagicMock()
    mock_callback2 = MagicMock()

    class MockTarget(Target):
        pass

    MockTarget.set_event_callback(event_type=None, event_callback=mock_callback1)
    MockTarget.set_event_callback(event_type=None, event_callback=mock_callback2)
    MockTarget.set_event_callback(event_type=Event.FUNC_EXEC, event_callback=mock_callback1)
    MockTarget.set_event_callback(event_type=Event.FUNC_EXEC, event_callback=mock_callback2)

    assert hasattr(MockTarget, "event_callbacks")

    event_callbacks = MockTarget.event_callbacks

    assert None in event_callbacks
    assert Event.FUNC_EXEC in event_callbacks

    assert len(event_callbacks[None]) == 2
    assert len(event_callbacks[Event.FUNC_EXEC]) == 2

    assert mock_callback1 in event_callbacks[None]
    assert mock_callback2 in event_callbacks[None]
    assert mock_callback1 in event_callbacks[Event.FUNC_EXEC]
    assert mock_callback2 in event_callbacks[Event.FUNC_EXEC]


def test_target_send_event():
    mock_callback1 = MagicMock()
    mock_callback2 = MagicMock()

    class MockTarget(Target):
        pass

    MockTarget.set_event_callback(event_type=None, event_callback=mock_callback1)
    MockTarget.set_event_callback(event_type=Event.FUNC_EXEC, event_callback=mock_callback2)

    mock_target = MockTarget()
    mock_target.send_event(None, test="None")
    mock_target.send_event(Event.FUNC_EXEC, test="FUNC_EXEC")

    calls = [
        call(mock_target, None, test="None"),
        call(mock_target, Event.FUNC_EXEC, test="FUNC_EXEC"),
    ]
    mock_callback1.assert_has_calls(calls)
    mock_callback2.assert_called_once_with(mock_target, Event.FUNC_EXEC, test="FUNC_EXEC")
