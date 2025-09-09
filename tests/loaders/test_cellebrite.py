from __future__ import annotations

from typing import TYPE_CHECKING, Callable

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.cellebrite import CellebriteFilesystem, CellebriteLoader
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target]) -> None:
    """Test that we correctly use ``CellebriteLoader`` when opening a ``Target``."""
    path = absolute_path("_data/loaders/cellebrite/EvidenceCollection.ufdx")

    target = opener(path)
    assert isinstance(target._loader, CellebriteLoader)
    assert target.path == path


def test_loader() -> None:
    """Test if we correctly detect and load a Cellebrite UFDX FFS zip extraction from DigitalCorpora (``iOS_17``).

    The content of the ``EXTRACTION_FFS.zip`` file has been replaced with a minimal linux folder structure
    for performance reasons.

    References:
        - https://corp.digitalcorpora.org/corpora/iOS17/
    """
    path = absolute_path("_data/loaders/cellebrite/EvidenceCollection.ufdx")

    loader = loader_open(path)
    assert isinstance(loader, CellebriteLoader)

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

    t = Target()
    loader.map(t)
    t.apply()

    assert len(t.filesystems) == 1
    assert isinstance(t.filesystems[0], CellebriteFilesystem)

    assert sorted(map(str, t.fs.path("/").iterdir())) == [
        "/$fs$",
        "/etc",
        "/home",
        "/opt",
        "/root",
        "/var",
    ]

    assert t.os == "linux"
    assert t.hostname == "example"
