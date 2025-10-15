from __future__ import annotations

from dissect.target.loader import open as loader_open
from dissect.target.loaders.nscollector import NSCollectorTarSubLoader
from dissect.target.loaders.tar import TarLoader
from dissect.target.target import Target
from tests._utils import absolute_path


def test_compressed_tar() -> None:
    """Test if we map a compressed NetScaler Collector tar image correctly."""
    path = absolute_path("_data/loaders/nscollector/collector_P_10.164.0.3_22Oct2025_11_31.tar.gz")

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    t = Target()
    loader.map(t)
    assert isinstance(loader.subloader, NSCollectorTarSubLoader)
    assert len(t.filesystems) == 1

    t.apply()
    test_file = t.fs.path("/nsconfig/ns.conf")
    assert test_file.exists()
    assert test_file.is_file()
    assert test_file.open().readline() == b"#NS14.1 Build 51.80\n"
