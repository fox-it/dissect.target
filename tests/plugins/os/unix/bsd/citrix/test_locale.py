from __future__ import annotations

from dissect.target.plugins.os.unix.bsd.citrix.locale import CitrixLocalePlugin
from dissect.target.target import Target
from tests._utils import absolute_path


def test_locale_nscollector() -> None:
    """Test that the Citrix locale plugin works as expected on NetScaler Collector packages."""
    path = absolute_path("_data/loaders/nscollector/collector_P_10.164.0.3_22Oct2025_11_31.tar.gz")

    t = Target.open(path)
    t.add_plugin(CitrixLocalePlugin)

    assert t.timezone == "UTC"
    assert t.language == []
