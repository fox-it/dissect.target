import pytest

from dissect.target import volume
from dissect.target.helpers import keychain

try:
    from dissect.target.volumes.bde import BitlockerVolumeSystem

    HAVE_DISSECT_FVE = True
except ModuleNotFoundError:
    HAVE_DISSECT_FVE = False


from ._utils import absolute_path


@pytest.fixture
def encrypted_volume():
    data_file = "data/enc-volume.bin"
    with open(absolute_path(data_file), "rb") as f:
        yield f


@pytest.mark.skipif(not HAVE_DISSECT_FVE, reason="requires dissect.fve")
def test_bde_volume_failure(target_win, encrypted_volume):
    enc_vol = volume.Volume(encrypted_volume, 1, 0, None, None, None, disk=encrypted_volume)
    target_win.volumes.add(enc_vol)
    target_win.volumes.apply()

    assert len(target_win.volumes) == 1
    assert enc_vol in target_win.volumes


@pytest.mark.skipif(not HAVE_DISSECT_FVE, reason="requires dissect.fve")
def test_bde_volume_with_recovery_key(target_win, encrypted_volume):

    recovery_key = "272316-265804-640728-713570-509047-503305-045837-324731"

    keychain.register_key(
        keychain.KeyType.RECOVERY_KEY,
        recovery_key,
        identifier=None,
        provider=BitlockerVolumeSystem.PROVIDER,
    )

    enc_vol = volume.Volume(encrypted_volume, 1, 0, None, None, None, disk=encrypted_volume)
    target_win.volumes.add(enc_vol)
    target_win.volumes.apply()

    assert len(target_win.volumes) == 2
    assert enc_vol in target_win.volumes

    dec_vol = next(v for v in target_win.volumes if v != enc_vol)

    # virtual fs + ntfs fs
    assert len(target_win.filesystems) == 2
    target_win.fs.mount("e:/", dec_vol.fs)

    assert target_win.fs.path("e:/test-folder/test-file-2.txt").exists()


@pytest.mark.skipif(not HAVE_DISSECT_FVE, reason="requires dissect.fve")
def test_bde_volume_with_passphrase(target_win, encrypted_volume):

    identifier = "B6AD258A-2725-4A42-93C6-844478BF7A90"
    passphrase = "Password1234"

    keychain.register_key(
        keychain.KeyType.PASSPHRASE,
        passphrase,
        identifier=identifier,
        provider=BitlockerVolumeSystem.PROVIDER,
    )

    enc_vol = volume.Volume(encrypted_volume, 1, 0, None, None, None, disk=encrypted_volume)
    target_win.volumes.add(enc_vol)
    target_win.volumes.apply()

    assert len(target_win.volumes) == 2
    assert enc_vol in target_win.volumes

    dec_vol = next(v for v in target_win.volumes if v != enc_vol)

    # virtual fs + ntfs fs
    assert len(target_win.filesystems) == 2
    target_win.fs.mount("e:/", dec_vol.fs)

    assert target_win.fs.path("e:/test-folder/test-file-2.txt").exists()


@pytest.mark.skipif(not HAVE_DISSECT_FVE, reason="requires dissect.fve")
def test_bde_volume_with_wildcard_key(target_win, encrypted_volume):

    keychain.register_wildcard_value("Password1234")

    enc_vol = volume.Volume(encrypted_volume, 1, 0, None, None, None, disk=encrypted_volume)
    target_win.volumes.add(enc_vol)
    target_win.volumes.apply()

    assert len(target_win.volumes) == 2
    assert enc_vol in target_win.volumes

    dec_vol = next(v for v in target_win.volumes if v != enc_vol)

    # virtual fs + ntfs fs
    assert len(target_win.filesystems) == 2
    target_win.fs.mount("e:/", dec_vol.fs)

    assert target_win.fs.path("e:/test-folder/test-file-2.txt").exists()
