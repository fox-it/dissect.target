import io
import urllib.parse
from pathlib import Path
from typing import Iterator
from unittest.mock import MagicMock, Mock, PropertyMock, call, patch

import pytest

from dissect.target.containers.raw import RawContainer
from dissect.target.exceptions import FilesystemError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.loader import LOADERS
from dissect.target.loaders.dir import DirLoader
from dissect.target.loaders.raw import RawLoader
from dissect.target.target import Event, Target, TargetLogAdapter, log


class ErrorCounter(TargetLogAdapter):
    errors = 0

    def error(*args, **kwargs):
        ErrorCounter.errors += 1


@pytest.mark.parametrize(
    "topo, entry_point, expected_result, expected_errors",
    [
        # Base cases:
        # Scenario 0:  Can we still load a single target that's not a dir?
        (["/raw.tst"], "/raw.tst", "[TestLoader('/raw.tst')]", 0),
        # Scenario 0b: Make sure we still get so see errors if a target fails to load
        # (1 error + 1 exception no load)
        (["/raw.vbox"], "/raw.vbox", "[]", 2),
        # Scenario 0c: Attempting to load a dir with nothing of interest yield an error
        # (1 exception no load)
        (["/dir/garbage"], "/dir", "[]", 1),
        # Dir cases:
        # Scenario 1:  Dir is loadable target (simple)
        (["/dir/etc", "/dir/var"], "/dir", "[DirLoader('/dir')]", 0),
        # Scenario 2: dir contains multiple loadable targets
        (["/dir/raw.img", "/dir/raw2.tst"], "/dir", "[RawLoader('/dir/raw.img'), TestLoader('/dir/raw2.tst')]", 0),
        # Scenario 2b: dir contains multiple loadable targets and some garbage
        # (it will wrap the garbage in a RawLoader to try)
        (
            ["/dir/raw.img", "/dir/raw2.tst", "/dir/info.txt"],
            "/dir",
            "[RawLoader('/dir/raw.img'), TestLoader('/dir/raw2.tst')," " RawLoader('/dir/info.txt')]",
            0,
        ),
        # Scenario 3: dir contains 1 loadable dir as well as 2 loadable targets
        (
            ["/dir/unix/etc", "/dir/unix/var", "/dir/raw.img", "/dir/raw2.tst"],
            "/dir",
            "[DirLoader('/dir/unix'), " "RawLoader('/dir/raw.img'), " "TestLoader('/dir/raw2.tst')]",
            0,
        ),
        # Scenario 3b: dir contains 2 loadable dirs as well as 2 loadable targets
        (
            [
                "/dir/unix/etc",
                "/dir/unix/var",
                "/dir/win/c:",
                "/dir/win/c:/windows/system32",
                "/dir/raw.img",
                "/dir/raw2.tst",
            ],
            "/dir",
            "[DirLoader('/dir/unix'), DirLoader('/dir/win'),"
            " RawLoader('/dir/raw.img'), TestLoader('/dir/raw2.tst')]",
            0,
        ),
        # Scenario 4: dir is a loadable dir but contains other files including loadable targets
        (
            [
                "/dir/etc",
                "/dir/var",
                "/dir/raw.img",
                "/dir/info.txt",
            ],
            "/dir",
            "[DirLoader('/dir')]",
            0,
        ),
        # Scenario 4b: Windows variant
        (
            [
                "/dir/c:",
                "/dir/c:/windows/system32",
                "/dir/raw.img",
                "/dir/info.txt",
            ],
            "/dir",
            "[DirLoader('/dir')]",
            0,
        ),
        # Scenario 5: Hypothetical Dirloader with selection
        (
            [
                "/dir/select.txt",  # selects 1 and 3
                "/dir/raw1.img",
                "/dir/raw2.img",
                "/dir/raw3.img",
            ],
            "/dir",
            "[SelectLdr('/dir/raw1.img'), SelectLdr('/dir/raw3.img')]",
            0,
        ),
    ],
)
@patch("dissect.target.target.getlogger", new=lambda t: ErrorCounter(log, {"target": t}))
def test_target_open_dirs(topo, entry_point, expected_result, expected_errors):
    # TestLoader to mix Raw Targets with Test Targets without depending on
    # specific implementations.
    class TestLoader(RawLoader):
        @staticmethod
        def detect(path: str) -> bool:
            return str(path).endswith(".tst")

        def map(self, target: Target):
            target.disks.add(RawContainer(io.BytesIO(b"\x00")))

    class SelectLdr(DirLoader):
        @staticmethod
        def detect(path: Path) -> bool:
            return path.is_dir() and path.joinpath("select.txt").exists()

        @staticmethod
        def find_all(path: Path) -> Iterator[Path]:
            return [Path("/dir/raw1.img"), Path("/dir/raw3.img")]

        def map(self, target: Target):
            target.disks.add(RawContainer(io.BytesIO(b"\x00")))

    if TestLoader not in LOADERS:
        LOADERS.append(TestLoader)
        LOADERS.append(SelectLdr)

    def make_vfs(topo: dict) -> dict:
        vfs = VirtualFilesystem()
        for entry in topo:
            if entry.find(".") > -1:
                vfs.map_file_fh(entry, io.BytesIO(b"\x00"))
            else:
                vfs.makedirs(entry)
        return vfs

    def dirtest(vfs: dict, selector: str) -> list:
        ErrorCounter.errors = 0
        try:
            return [x._loader for x in Target.open_all([vfs.path(selector)])]
        except Exception:
            ErrorCounter.errors += 1
            return []

    assert str(dirtest(make_vfs(topo), entry_point)) == expected_result

    assert ErrorCounter.errors == expected_errors


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
