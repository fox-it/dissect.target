from __future__ import annotations

import logging
import os
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, Generic, TypeVar

from dissect.target.helpers.lazy import import_lazy
from dissect.target.helpers.loaderutil import parse_path_uri

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

__all__ = [
    "Loader",
    "RawLoader",
    "open",
    "register",
]

log = logging.getLogger(__name__)

DirLoader: Loader = import_lazy("dissect.target.loaders.dir").DirLoader
"""A lazy loaded :class:`dissect.target.loaders.dir.DirLoader`."""

RawLoader: Loader = import_lazy("dissect.target.loaders.raw").RawLoader
"""A lazy loaded :class:`dissect.target.loaders.raw.RawLoader`."""

LOADERS: list[Loader] = []
LOADERS_BY_SCHEME: dict[str, Loader] = {
    "dir": DirLoader,
    "raw": RawLoader,
}
MODULE_PATH = "dissect.target.loaders"


class Loader:
    """A base class for loading a specific path and coupling it to a :class:`Target <dissect.target.target.Target>`.

    Implementors of this class are responsible for mapping any type of source data
    to a :class:`Target <dissect.target.target.Target>`.
    Whether that's to map all VMDK files from a VMX or mapping the contents of a zip file to a virtual filesystem,
    if it's something that can be translated to a "disk", "volume" or "filesystem", you can write a loader that
    maps it into a target.

    You can do anything you want to manipulate the :class:`Target <dissect.target.target.Target>` object
    in your ``map`` function, but generally you do one of the following:

    * open a :class:`Container <dissect.target.container.Container>` and add it to ``target.disks``.
    * open a :class:`Volume <dissect.target.volume.Volume>` and add it to ``target.volumes``.
    * open a :class:`VirtualFilesystem <dissect.target.filesystem.VirtualFilesystem>`,\
    add your files into it and add it to ``target.filesystems``.

    You don't need to manually parse volumes or filesystems in your loader, just add the highest level object you have
    (e.g. a :class:`Container <dissect.target.container.Container>` of a VMDK file) to the target.
    However, sometimes you need to get creative.
    Take a look at the :class:`ITunesLoader <dissect.target.loaders.itunes.ITunesLoader>` and
    :class:`TarLoader <dissect.target.loaders.tar.TarLoader>` for some creative examples.

    Args:
        path: The target path to load.
        parsed_path: A URI parsed path to use.
    """

    def __init__(
        self, path: Path, *, parsed_path: urllib.parse.ParseResult | None = None, resolve: bool = True, **kwargs
    ):
        self.path = path
        self.absolute_path = None
        if resolve:
            try:
                self.absolute_path = path.resolve()
            except Exception:
                log.debug("Failed to resolve loader path %r", path)
                self.absolute_path = path
            self.base_path = self.absolute_path.parent
        self.parsed_path = parsed_path
        self.parsed_query = (
            dict(urllib.parse.parse_qsl(parsed_path.query, keep_blank_values=True)) if parsed_path else {}
        )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({str(self.path)!r})"

    @staticmethod
    def detect(path: Path) -> bool:
        """Detects wether this ``Loader`` class can load this specific ``path``.

        Args:
            path: The target path to check.

        Returns:
            ``True`` if the ``path`` can be loaded by a ``Loader`` instance. ``False`` otherwise.
        """
        raise NotImplementedError

    @staticmethod
    def find_all(path: Path, parsed_path: urllib.parse.ParseResult | None = None) -> Iterator[str | Path]:
        """Finds all targets to load from ``path``.

        This can be used to open multiple targets from a target path that doesn't necessarily map to files on a disk.
        For example, a wildcard in a hostname a loader that opens targets from an API or Unix socket,
        such as the Carbon Black loader.

        Args:
            path: The location to a target to try and open multiple paths from.
            parsed_path: A URI parsed path to use.

        Returns:
            All the target paths found from the source path.
        """
        yield path

    def map(self, target: Target) -> None:
        """Maps the loaded path into a ``Target``.

        Args:
            target: The target that we're mapping into.
        """
        raise NotImplementedError


T = TypeVar("T")


class SubLoader(Loader, Generic[T]):
    """A base class for loading arbitary data and coupling it to a :class:`Target <dissect.target.target.Target>`.

    Should not be called like a regular :class:`Loader`. For examples see :class:`TarLoader`
    and :class:`TarSubLoader` implementations.
    """

    def __init__(
        self,
        path: Path,
        value: T,
        *,
        parsed_path: urllib.parse.ParseResult | None = None,
        resolve: bool = True,
        **kwargs,
    ):
        super().__init__(path, parsed_path=parsed_path, resolve=resolve, **kwargs)

    @staticmethod
    def detect(path: Path, value: T) -> bool:
        raise NotImplementedError

    def map(self, target: Target) -> None:
        raise NotImplementedError


def register(module_name: str, class_name: str, internal: bool = True) -> None:
    """Registers a ``Loader`` class inside ``LOADERS``.

    This function registers a loader using ``modname`` relative to the ``MODULE_PATH``.
    It lazily imports the module, and retrieves the specific class from it.

    Args:
        module: The module where to find the loader.
        class_name: The class to load.
        internal: Whether it is an internal module or not.
    """
    module = f"{MODULE_PATH}.{module_name}" if internal else module_name

    loader = getattr(import_lazy(module), class_name)
    LOADERS.append(loader)
    LOADERS_BY_SCHEME[module_name] = loader


def find_loader(
    path: str | Path,
    *,
    fallbacks: list[type[Loader]] | None = None,
) -> type[Loader] | None:
    """Finds a :class:`Loader` class for a given path.

    This searches for a specific :class:`Loader` classs that is able to load a target pointed to by ``path``.
    Once it detects a suitable :class:`Loader` it immediately returns said :class:`Loader` class.

    The :class:`DirLoader <dissect.target.loaders.dir.DirLoader>` is used as the last entry
    due to how the detection methods function.

    Args:
        path: The target path to load.
        fallbacks: Fallback loaders to try.

    Returns:
        A :class:`Loader` class for the specific target if one is found.
    """
    path = Path(path) if not isinstance(path, os.PathLike) else path

    if fallbacks is None:
        fallbacks = [DirLoader]

    for loader in LOADERS + fallbacks:
        try:
            if loader.detect(path):
                return loader
        except ImportError as e:  # noqa: PERF203
            log.info("Failed to import %s", loader)
            log.debug("", exc_info=e)

    return None


def find_loader_by_scheme(scheme: str) -> type[Loader] | None:
    """Finds a :class:`Loader` class by its scheme.

    Args:
        scheme: The scheme to find the loader for.

    Returns:
        A :class:`Loader` class for the specific scheme if one is found.
    """
    return LOADERS_BY_SCHEME.get(scheme)


def open(path: str | Path, *, fallbacks: list[type[Loader]] | None = None, **kwargs) -> Loader | None:
    """Opens a :class:`Loader` for a given path.

    This instantiates a :class:`Loader` for a specific ``path``.
    The :class:`DirLoader <dissect.target.loaders.dir.DirLoader>` is used as the last entry
    due to how the detection methods function.

    Args:
        path: The target path to load.

    Returns:
        A :class:`Loader` instance for the specific target if one is found.
    """
    adjusted_path, parsed_path = parse_path_uri(path)

    if parsed_path is not None and (loader := find_loader_by_scheme(parsed_path.scheme)):
        # If we find a loader by scheme, use the adjusted path
        kwargs["parsed_path"] = parsed_path
        return loader(adjusted_path, **kwargs)

    # Use the original unadjusted path
    path = Path(path) if not isinstance(path, os.PathLike) else path
    if loader := find_loader(path, fallbacks=fallbacks):
        kwargs["parsed_path"] = parsed_path
        return loader(path, **kwargs)

    return None


register("local", "LocalLoader")
register("asdf", "AsdfLoader")
register("vmx", "VmxLoader")
register("vmwarevm", "VmwarevmLoader")
register("hyperv", "HyperVLoader")
register("pvs", "PvsLoader")
register("pvm", "PvmLoader")
register("utm", "UtmLoader")
register("libvirt", "LibvirtLoader")
register("proxmox", "ProxmoxLoader")
register("ovf", "OvfLoader")
register("ova", "OvaLoader")
register("vbox", "VBoxLoader")
register("vb", "VBLoader")
register("vbk", "VbkLoader")
register("xva", "XvaLoader")
register("vma", "VmaLoader")
register("kape", "KapeLoader")
register("velociraptor", "VelociraptorLoader")
register("tanium", "TaniumLoader")
register("itunes", "ITunesLoader")
register("ab", "AndroidBackupLoader")
register("cellebrite", "CellebriteLoader")
register("target", "TargetLoader")
# Disabling ResLoader because of DIS-536
# register("res", "ResLoader")
register("overlay2", "Overlay2Loader")
register("overlay", "OverlayLoader")
register("phobos", "PhobosLoader")
register("uac", "UacLoader")
# tar and zip loaders should be low priority to give other loaders a chance first
register("tar", "TarLoader")
register("zip", "ZipLoader")
# These are URI based loaders, so just put them low down the list since they don't do any detection anyway
register("smb", "SmbLoader")
register("cb", "CbLoader")
register("cyber", "CyberLoader")
register("log", "LogLoader")
register("remote", "RemoteLoader")
register("mqtt", "MqttLoader")
register("multiraw", "MultiRawLoader")  # Should be last
