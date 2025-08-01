from __future__ import annotations

import io
import logging
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.target.exceptions import ContainerError
from dissect.target.helpers.lazy import import_lazy
from dissect.target.helpers.utils import readinto

if TYPE_CHECKING:
    from dissect.target.volume import VolumeSystem

CONTAINERS: list[type[Container]] = []
MODULE_PATH = "dissect.target.containers"

RawContainer = import_lazy("dissect.target.containers.raw").RawContainer
"""A lazy import of :mod:`dissect.target.containers.raw`."""

log = logging.getLogger(__name__)


class Container(io.IOBase):
    """Base class that acts as a file-like object wrapper around anything that can behave like a "raw disk".

    Containers are anything from raw disk images and virtual disks, to evidence containers and made-up binary formats.
    Consumers of the ``Container`` class only need to implement ``seek``, ``tell`` and ``read``.
    Override ``__init__`` for any opening that you may need to do, but don't forget to initialize the super class.

    Args:
        fh: The source file-like object of the container or a ``Path`` object to the file.
        size: The size of the container.
        vs: An optional shorthand to set the underlying volume system, usually set later.
    """

    # Due to lazy importing we generally can't use isinstance(), so we add a short identifying string to each class
    # This has the added benefit of having a readily available "pretty name" for each implementation
    __type__: str = None
    """A short string identifying the type of container."""

    def __init__(self, fh: BinaryIO | Path, size: int, vs: VolumeSystem | None = None):
        self.fh = fh
        self.size = size

        # Shorthand access to vs
        self.vs = vs

        if self.__type__ is None:
            raise NotImplementedError(f"{self.__class__.__name__} must define __type__")

    def __repr__(self) -> str:
        return f"<Container type={self.__type__} size={self.size} vs={self.vs.__type__ if self.vs else None}>"

    @classmethod
    def detect(cls, item: list | BinaryIO | Path) -> bool:
        """Detect if this ``Container`` can handle this file format.

        Args:
            item: The object we want to see if it can be handled by this ``Container``.

        Returns:
            ``True`` if this ``Container`` can be used, ``False`` otherwise.
        """
        i = item[0] if isinstance(item, list) else item
        if hasattr(i, "read"):
            return cls.detect_fh(i, item)
        if cls.detect_path(i, item):
            return True
        if i.exists():
            with i.open("rb") as fh:
                return cls.detect_fh(fh, item)

        return False

    @classmethod
    def detect_fh(cls, fh: BinaryIO, original: list | BinaryIO) -> bool:
        """Detect if this ``Container`` can be used to open the file-like object ``fh``.

        The function checks whether the raw data contains any magic information that corresponds to this
        specific container.

        Args:
            fh: A file-like object that we want to open a ``Container`` on.
            original: The original argument passed to ``detect()``.

        Returns:
            ``True`` if this ``Container`` can be used for this file-like object, ``False`` otherwise.
        """
        offset = fh.tell()
        try:
            fh.seek(0)
            return cls._detect_fh(fh, original)
        except NotImplementedError:
            raise
        except Exception as e:
            log.warning("Failed to detect %s container", cls.__name__)
            log.debug("", exc_info=e)
        finally:
            fh.seek(offset)

        return False

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        """Detect if this ``Container`` can be used to open the file-like object ``fh``.

        This method should be implemented by subclasses. The position of ``fh`` is guaranteed to be ``0``.

        Args:
            fh: A file-like object that we want to open a ``Container`` on.
            original: The original argument passed to ``detect()``.

        Returns:
            ``True`` if this ``Container`` can be used for this file-like object, ``False`` otherwise.
        """
        raise NotImplementedError

    @staticmethod
    def detect_path(path: Path, original: list | Path) -> bool:
        """Detect if this ``Container`` can be used to open ``path``.

        The function checks wether file inside ``path`` is formatted in such a way that
        this ``Container`` can be used to read it. For example, it validates against the
        file extension.

        Args:
            path: A location to a file.
            original: The original argument passed to ``detect()``.

        Returns:
            ``True`` if this ``Container`` can be used for this path, ``False`` otherwise.
        """
        raise NotImplementedError

    def read(self, length: int = -1) -> bytes:
        """Read a ``length`` of bytes from this ``Container``."""
        raise NotImplementedError

    def readinto(self, b: bytearray) -> int:
        """Uses :func:`dissect.target.helpers.utils.readinto`."""
        return readinto(buffer=b, fh=self)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        """Change the stream position to ``offset``.

        ``whence`` determines where to seek from:

        * ``io.SEEK_SET`` (``0``):: absolute offset in the stream.
        * ``io.SEEK_CUR`` (``1``):: current position in the stream.
        * ``io.SEEK_END`` (``2``):: end of stream.

        Args:
            offset: The offset relative to the position indicated by ``whence``.
            whence: Where to start the seek from.
        """
        raise NotImplementedError

    def seekable(self) -> bool:
        """Returns whether ``seek`` can be used by this ``Container``. Always ``True``."""
        return True

    def tell(self) -> int:
        """Returns the current seek position of the ``Container``."""
        raise NotImplementedError

    def close(self) -> None:
        """Close the container.

        Override this if you need to clean-up anything.
        """


def register(module: str, class_name: str, internal: bool = True) -> None:
    """Register a container implementation to use when opening a container.

    This function registers a container using ``module`` relative to the ``MODULE_PATH``.
    It lazily imports the module, and retrieves the specific class from it.

    Args:
        module: The module where to find the container.
        class_name: The class to load.
        internal: Whether it is an internal module or not.
    """

    if internal:
        module = f"{MODULE_PATH}.{module}"

    CONTAINERS.append(getattr(import_lazy(module), class_name))


def open(item: list | str | BinaryIO | Path, *args, **kwargs) -> Container:
    """Open a :class:`Container` from the given object.

    All currently supported containers are checked to find a compatible one.
    :class:`RawContainer <dissect.target.containers.raw.RawContainer>` must always be checked last
    since it always succeeds!

    Args:
        item: The object we want to open a :class`Container` from.

    Raises:
        ContainerError: When a compatible :class`Container` was found but it failed to open.
        ContainerError: When no compatible :class`Container` implementations were found.
    """
    if isinstance(item, list):
        item = [Path(entry) if isinstance(entry, str) else entry for entry in item]
    elif isinstance(item, str):
        item = Path(item)

    first = item[0] if isinstance(item, list) else item
    first_fh = None
    first_fh_opened = False
    first_fh_offset = None
    first_path = None

    if hasattr(first, "read"):
        first_fh = first
    else:
        first_path = first
        if first_path.is_file():
            first_fh = first.open("rb")
            first_fh_opened = True

    if first_fh:
        first_fh_offset = first_fh.tell()
        first_fh.seek(0)

    try:
        for container in [*CONTAINERS, RawContainer]:
            try:
                # Path must be leading for things like SplitContainer, but fall back to fh if we have one
                if (first_path and container.detect_path(first_path, item)) or (
                    first_fh and container.detect_fh(first_fh, item)
                ):
                    return container(item, *args, **kwargs)
            except ImportError as e:  # noqa: PERF203
                log.info("Failed to import %s", container)
                log.debug("", exc_info=e)
            except Exception as e:
                raise ContainerError(f"Failed to open container {item}") from e
    finally:
        if first_fh_opened:
            first_fh.close()
        elif first_fh:
            first_fh.seek(first_fh_offset)

    raise ContainerError(f"Failed to detect container for {item}")


register("ewf", "EwfContainer")
register("vmdk", "VmdkContainer")
register("vhdx", "VhdxContainer")
register("vhd", "VhdContainer")
register("qcow2", "QCow2Container")
register("vdi", "VdiContainer")
register("hdd", "HddContainer")
register("hds", "HdsContainer")
register("split", "SplitContainer")
register("fortifw", "FortiFirmwareContainer")
