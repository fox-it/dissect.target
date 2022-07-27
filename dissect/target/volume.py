import io
import logging
from typing import ByteString, List

from dissect.target.exceptions import VolumeSystemError
from dissect.target.helpers import keychain
from dissect.target.helpers.lazy import import_lazy
from dissect.target.helpers.utils import readinto

disk = import_lazy("dissect.target.volumes.disk")
lvm = import_lazy("dissect.target.volumes.lvm")
vmfs = import_lazy("dissect.target.volumes.vmfs")
bde = import_lazy("dissect.target.volumes.bde")

log = logging.getLogger(__name__)

LOGICAL_VOLUME_MANAGERS = [lvm.LvmVolumeSystem, vmfs.VmfsVolumeSystem]

ENCRYPTED_VOLUME_MANAGERS = [bde.BitlockerVolumeSystem]


class VolumeSystem:
    def __init__(self, fh, dsk=None, serial=None):
        self.fh = fh
        self.disk = dsk or fh  # Provide shorthand access to source disk
        self.serial = serial
        self._volumes_list = None

    def __repr__(self):
        return f"<{self.__class__.__name__} serial={self.serial}>"

    @staticmethod
    def detect(fh):
        """
        Volume system implementations must implement this and return True or False if they can read the volume system
        """
        raise NotImplementedError()

    def _volumes(self):
        """
        Volume system implementations must implement this and yield all valid found partitions
        """
        raise NotImplementedError()

    def readinto(self, b: ByteString) -> int:
        return readinto(buffer=b, fh=self.fh)

    @property
    def volumes(self):
        if self._volumes_list is None:
            self._volumes_list = list(self._volumes())

        return self._volumes_list


class EncryptedVolumeSystem(VolumeSystem):

    PROVIDER = None

    def __init__(self, fh, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)

        if not self.PROVIDER:
            raise ValueError("Provider identifier is not set")
        self.keys = keychain.get_keys_for_provider(self.PROVIDER) + keychain.get_keys_without_provider()

    def get_keys_for_identifier(self, identifier: str) -> List[keychain.Key]:
        return [key for key in self.keys if key.identifier and key.identifier.lower() == identifier.lower()]

    def get_keys_for_identifiers(self, identifiers: List[str]) -> List[keychain.Key]:
        # normalise values before checks
        identifiers = [i.lower() for i in identifiers]
        return [key for key in self.keys if key.identifier and key.identifier.lower() in identifiers]

    def get_keys_without_identifier(self) -> List[keychain.Key]:
        return [key for key in self.keys if key.identifier is None]


class LogicalVolumeSystem(VolumeSystem):
    @staticmethod
    def detect_volume(fh):
        raise NotImplementedError()

    @classmethod
    def open_all(cls, volumes):
        raise NotImplementedError()


class Volume(io.IOBase):
    def __init__(
        self,
        fh,
        number,
        offset,
        size,
        vtype,
        name,
        guid=None,
        raw=None,
        disk=None,
        vs=None,
        fs=None,
        drive_letter=None,
    ):
        self.fh = fh
        self.number = number
        self.offset = offset
        self.size = size
        self.type = vtype
        self.name = name
        self.guid = guid

        # Shorthand access to raw volume, disk, vs and fs objects
        self.raw = raw
        self.disk = disk
        self.vs = vs
        self.fs = fs
        self.drive_letter = drive_letter

        self.seek(0)

    def __repr__(self):
        return f"<Volume name={self.name!r} size={self.size!r} fs={self.fs!r}>"

    def read(self, length):
        return self.fh.read(length)

    def seek(self, offset, whence=io.SEEK_SET):
        return self.fh.seek(offset, whence)

    def tell(self):
        return self.fh.tell()

    def seekable(self):
        return True


def open(fh, *args, **kwargs):
    try:
        return disk.DissectVolumeSystem(fh)
    except Exception as e:
        raise VolumeSystemError(f"Failed to load volume system for {fh}", cause=e)


def is_lvm_volume(vol):
    for logical_vs in LOGICAL_VOLUME_MANAGERS:
        try:
            if logical_vs.detect_volume(vol):
                return True
        except ImportError as e:
            log.warning("Failed to import %s", logical_vs, exc_info=e)
        except Exception as e:
            raise VolumeSystemError(f"Failed to detect logical volume for {vol}", cause=e)

    return False


def is_encrypted(volume) -> bool:
    for manager in ENCRYPTED_VOLUME_MANAGERS:
        try:
            if manager.detect(volume):
                return True
        except ImportError as e:
            log.warning("Failed to import %s", manager, exc_info=e)
        except Exception as e:
            raise VolumeSystemError(f"Failed to detect encrypted volume for {volume}", cause=e)
    return False


def open_encrypted(volume: Volume) -> Volume:
    for manager_cls in ENCRYPTED_VOLUME_MANAGERS:
        try:
            if manager_cls.detect(volume):
                volume_manager = manager_cls(volume)
                yield from volume_manager.volumes
        except VolumeSystemError:
            log.exception(f"Failed to open an encrypted volume {volume} with volume manager {manager_cls}")
    return None


def open_lvm(volumes, *args, **kwargs):
    for logical_vs in LOGICAL_VOLUME_MANAGERS:
        try:
            for lv in logical_vs.open_all(volumes):
                yield lv
        except ImportError as e:
            log.warning("Failed to import %s", logical_vs, exc_info=e)
        except Exception as e:
            raise VolumeSystemError(f"Failed to load logical volume system for {volumes}", cause=e)
