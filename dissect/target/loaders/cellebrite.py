from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from defusedxml import ElementTree as ET

from dissect.target.filesystem import LayerFilesystem
from dissect.target.filesystems.zip import ZipFilesystem
from dissect.target.helpers import configutil
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from pathlib import Path
    from uuid import UUID

    from dissect.target.target import Target

log = logging.getLogger(__name__)


@dataclass
class Extraction:
    type: str | None
    path: Path


@dataclass
class DeviceInfo:
    vendor: str
    model: str
    fguid: UUID | None = None
    guid: UUID | None = None
    os: str | None = None


@dataclass
class Ufdx:
    path: Path | None = None
    evidence: UUID | None = None
    device: DeviceInfo | None = None
    extractions: list[Extraction] | None = None


@dataclass
class Dump:
    type: str
    path: Path


@dataclass
class Keychain:
    type: str
    path: Path


@dataclass
class Ufd:
    path: Path
    device: DeviceInfo
    dumps: list[Dump] | None = None


class CellebriteLoader(Loader):
    """Load Cellebrite UFED exports (``.ufdx`` and ``.ufd``).

    References:
        - https://corp.digitalcorpora.org/corpora/mobile
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)

        self.ufdx = None
        self.ufd = []
        self.ffs = None

        # Parse xml to find .ufd path
        if path.suffix == ".ufdx":
            try:
                tree = ET.fromstring(path.read_text())

                self.ufdx = Ufdx(
                    path=path,
                    evidence=tree.get("EvidenceID"),
                    device=DeviceInfo(**{k.lower(): v for k, v in tree.find("DeviceInfo").attrib.items()}),
                    extractions=[],
                )

                for extraction in tree.findall("Extractions/Extraction"):
                    self.ufdx.extractions.append(
                        Extraction(
                            type=extraction.get("TransferType"),
                            path=self.base_path.joinpath(extraction.get("Path").replace("\\", "/")),
                        )
                    )

            except ET.ParseError as e:
                raise ValueError(f"Invalid XML in {path}: {e}")

        elif path.suffix == ".ufd":
            self.ufdx = Ufdx(extractions=[Extraction(type=None, path=self.absolute_path)])

        else:
            raise ValueError(f"Unknown suffix {path.suffix} for {path}")

        # Not implemented: parse ufd ini to find ffs, could replace ``Extraction()`` with ``Ufd()``.

        for extraction in self.ufdx.extractions:
            if not extraction.path.is_file():
                log.warning("Extraction %s does not exist", extraction.path)
                continue

            config = configutil.parse(extraction.path, hint="ini")
            device = {k.lower(): v for k, v in config.get("DeviceInfo").items()}
            device["model"] += f" ({device['devicemodel']})"
            del device["devicemodel"]

            ufd = Ufd(
                path=extraction.path,
                device=DeviceInfo(**device),
                dumps=[],
            )

            for type, dump in config.get("Dumps").items():
                dump_path = ufd.path.resolve().parent.joinpath(dump)
                ufd.dumps.append(Dump(type=type, path=dump_path))

            self.ufd.append(ufd)

    @staticmethod
    def detect(path: Path) -> bool:
        return path.is_file() and path.suffix in [".ufdx", ".ufd"]

    def map(self, target: Target) -> None:
        for ufd in self.ufd:
            for dump in ufd.dumps:
                # Keychain dumps are inside the same FFS zip file, so we let the CellebriteFilesystem handle mounting
                # that so we prevent an extra file handle being opened.
                if dump.type != "FileDump":
                    log.warning("Ignoring Cellebrite dump %s of type %s", dump.path.name, dump.type)
                    continue

                if (size := dump.path.lstat().st_size) > 1_000_000_000:
                    log.warning(
                        "Cellebrite filesystem dump %s is %s GB, this might take a while..",
                        dump.path.name,
                        size // 1024 // 1024 // 1024,
                    )

                target.filesystems.add(CellebriteFilesystem(dump.path))


class CellebriteFilesystem(LayerFilesystem):
    """Cellebrite ``FileDump`` filesystem implementation."""

    __type__ = "cellebrite"

    def __init__(self, path: Path, base: str | None = None, **kwargs):
        super().__init__(**kwargs)
        self.source = path

        if path.suffix == ".zip":
            fs = ZipFilesystem(path.open("rb"), base=base)
        else:
            raise ValueError(f"Unsupported Cellebrite dump type {path.name}")

        # We add the full file system from ``/filesystem1`` as a layer to the root ``/`` and
        # mount found extras and extraction metadata, such as keychain dumps to folders in ``/$fs$/fs0``,
        # to keep this information accessible for device specific plugins.
        for fs_dir, dest in [
            ("/filesystem1", "/"),
            ("/extra", "/$fs$/fs0/extra"),
            ("/metadata1", "/$fs$/fs0/metadata"),
        ]:
            if fs.path(fs_dir).exists():
                # Mounts the ZipFilesystem at the provided fs_dir base. This way we can
                # (ab)use a single zip file handle for multiple filesystem layers.
                self.append_layer().mount(dest, fs, base=fs_dir)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.source}>"
