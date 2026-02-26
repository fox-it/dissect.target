import csv
import gzip
from io import BytesIO, TextIOWrapper
from pathlib import Path
from unittest.mock import patch

import pytest
from dissect.util.stream import MappingStream

from dissect.target.containers.raw import RawContainer
from dissect.target.exceptions import FileDecryptionError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers import keychain
from dissect.target.plugins.os.unix.linux.android._os import AndroidPlugin
from dissect.target.target import Target
from dissect.target.volume import Volume
from tests._utils import absolute_path


def map_stream_from_csv(csv_path: Path, size: int, align: int = 8192) -> MappingStream:
    stream = MappingStream(align=align, size=size)
    with TextIOWrapper(gzip.open(csv_path, "r")) as fh:
        for offset, data in csv.reader(fh):
            offset = int(offset)
            data = bytes.fromhex(data)
            stream.add(offset, len(data), BytesIO(data))
    return stream


@pytest.fixture
def avd_disks_with_pin() -> tuple[MappingStream, MappingStream]:
    return map_stream_from_csv(
        absolute_path("_data/plugins/os/unix/linux/android/avd/userdata_with_pin.csv.gz"),
        size=6442450944,
    ), map_stream_from_csv(
        absolute_path("_data/plugins/os/unix/linux/android/avd/metadata_with_pin.csv.gz"),
        size=18874368,
    )


@pytest.fixture
def avd_disks_without_pin() -> tuple[MappingStream, MappingStream]:
    return map_stream_from_csv(
        absolute_path("_data/plugins/os/unix/linux/android/avd/userdata_without_pin.csv.gz"),
        size=6442450944,
    ), map_stream_from_csv(
        absolute_path("_data/plugins/os/unix/linux/android/avd/metadata_without_pin.csv.gz"),
        size=18874368,
    )


def test_android_os(target_android: Target) -> None:
    target_android.add_plugin(AndroidPlugin)

    assert target_android.os == "android"
    assert target_android.version == "Android 4.4.2 (2013-10-31)"
    assert target_android.hostname == "TMG28071935"


@pytest.mark.parametrize(
    ("build_prop_locations"),
    [
        ([("/build.prop", "build.prop")]),
        ([("/system/build.prop", "build.prop")]),
        ([("/build.prop", "build.prop"), ("/foo/build.prop", "another.prop")]),
    ],
)
def test_android_os_detect_props(target_bare: Target, build_prop_locations: list[tuple[str, str]]) -> None:
    """Test if we detect different build.prop locations correctly."""

    fs = VirtualFilesystem()
    fs.makedirs("/data")
    fs.makedirs("/system")
    fs.makedirs("/vendor")
    fs.makedirs("/product")

    for prop, prop_file in build_prop_locations:
        fs.map_file(prop, absolute_path(f"_data/plugins/os/unix/linux/android/{prop_file}"))

    # prop file that should not be found
    fs.map_file_fh("/foo/bar/too/deep/build.prop", BytesIO(b"ro.not.found='true'"))

    target_bare._os_plugin = AndroidPlugin
    target_bare.filesystems.add(fs)
    target_bare.apply()

    target_bare.add_plugin(AndroidPlugin)

    assert target_bare.os == "android"
    assert sorted(map(str, target_bare._os.build_prop_paths)) == sorted(p for p, _ in build_prop_locations)
    assert target_bare._os.props
    assert target_bare.hostname == "TMG28071935"

    # test if mutual exclusive properties from different build.prop files are added to the dict.
    if "/foo/build.prop" in target_bare._os.build_prop_paths:
        assert target_bare._os.props.get("ro.foo") == "bar"

    # test if glob does not go too deep.
    assert "/foo/bar/too/deep/build.prop" not in target_bare._os.build_prop_paths


def test_android_os_unlock_credential_encrypted_volume_with_pin(
    target_bare: Target, avd_disks_with_pin: tuple[MappingStream, MappingStream]
) -> None:
    userdata_fh, metadata_fh = avd_disks_with_pin
    target_bare.disks.add(RawContainer(metadata_fh))
    target_bare.volumes.add(Volume(userdata_fh, 1, 0, userdata_fh.size, None, "userdata"))
    target_bare.apply()

    assert isinstance(target_bare._os, AndroidPlugin)
    assert target_bare._os.userdata_partition_unlocked
    assert target_bare._os.device_encrypted_storage_unlocked
    assert not target_bare._os.credential_encrypted_storage_unlocked

    # Verify we can find the credential encrypted userdata directory, but not read it
    encrypted_userdata = target_bare.fs.get("/data/data")

    # Should be not be able to list the encrypted userdata directory yet
    with pytest.raises(FileDecryptionError):
        encrypted_userdata.listdir()

    with patch.object(keychain, "KEYCHAIN", []):
        keychain.register_key(
            keychain.KeyType.PASSPHRASE,
            b"30031853",  # Birthday of a legend
            identifier=None,
            provider="android",
        )
        target_bare._os.unlock()
        assert target_bare._os.credential_encrypted_storage_unlocked

    # Verify we can now list the encrypted userdata directory
    assert "com.google.android.apps.photos" in encrypted_userdata.listdir()


def test_android_os_unlock_credential_encrypted_volume_without_pin(
    target_bare: Target, avd_disks_without_pin: tuple[MappingStream, MappingStream]
) -> None:
    userdata_fh, metadata_fh = avd_disks_without_pin
    target_bare.disks.add(RawContainer(metadata_fh))
    target_bare.volumes.add(Volume(userdata_fh, 1, 0, userdata_fh.size, None, "userdata"))
    target_bare.apply()

    assert isinstance(target_bare._os, AndroidPlugin)

    # As this device doesn't have a PIN/password/pattern set, all storages should be unlocked automatically
    assert target_bare._os.userdata_partition_unlocked
    assert target_bare._os.device_encrypted_storage_unlocked
    assert target_bare._os.credential_encrypted_storage_unlocked

    # Verify we can list the encrypted userdata directory
    assert "com.google.android.apps.photos" in target_bare.fs.get("/data/data/").listdir()
