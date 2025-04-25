from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.loaders.cellebrite import CellebriteFilesystem, CellebriteLoader
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_cellebrite_loader(target_bare: Target) -> None:
    """Test if we correctly detect and load a Cellebrite UFDX FFS zip extraction from DigitalCorpora (``iOS_17``).

    The content of the ``EXTRACTION_FFS.zip`` file has been replaced with a minimal linux folder structure
    for performance reasons.

    Resources:
        - https://corp.digitalcorpora.org/corpora/iOS17/
    """
    path = Path(absolute_path("_data/loaders/cellebrite/EvidenceCollection.ufdx"))
    loader = CellebriteLoader(path)

    assert loader.ufdx.path.name == "EvidenceCollection.ufdx"
    assert loader.ufdx.evidence == "00f905b7-5131-42d9-9ccf-2227115d9536"
    assert loader.ufdx.device.vendor == "Apple"
    assert loader.ufdx.device.model == "iPhone 11 (N104AP)"
    assert loader.ufdx.device.fguid == "98ec76e1-a885-4733-91dd-5dbb61156335"
    assert loader.ufdx.device.guid == "98ec76e1-a885-4733-91dd-5dbb61156335"
    assert not loader.ufdx.device.os
    assert len(loader.ufdx.extractions) == 1
    assert loader.ufdx.extractions[0].type == "FileSystemDump"
    assert loader.ufdx.extractions[0].path.name == "EXTRACTION_FFS.ufd"

    assert len(loader.ufd) == 1
    assert loader.ufd[0].path.name == "EXTRACTION_FFS.ufd"
    assert loader.ufd[0].device.vendor == "Apple"
    assert loader.ufd[0].device.model == "iPhone 11 (N104AP)"
    assert not loader.ufd[0].device.fguid
    assert not loader.ufd[0].device.guid
    assert loader.ufd[0].device.os == "17.3 (21D50)"
    assert len(loader.ufd[0].dumps) == 2
    assert loader.ufd[0].dumps[0].type == "FileDump"
    assert loader.ufd[0].dumps[0].path.name == "EXTRACTION_FFS.zip"
    assert loader.ufd[0].dumps[1].type == "Keychain"

    loader.map(target_bare)
    target_bare.apply()

    assert len(target_bare.filesystems) == 1
    assert isinstance(target_bare.filesystems[0], CellebriteFilesystem)

    assert sorted(map(str, target_bare.fs.path("/").iterdir())) == [
        "/$fs$",
        "/etc",
        "/home",
        "/opt",
        "/root",
        "/var",
    ]

    assert target_bare.os == "linux"
    assert target_bare.hostname == "example"
