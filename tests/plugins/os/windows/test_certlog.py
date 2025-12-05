from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows import certlog
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem


def test_certlog_plugin(target_win: Target, fs_win: VirtualFilesystem) -> None:
    ca_edb = absolute_path("_data/plugins/os/windows/certlog/SEVENKINGDOMS-CA.edb")

    fs_win.map_file("Windows/System32/Certlog/SEVENKINGDOMS-CA.edb", ca_edb)

    target_win.add_plugin(certlog.CertLogPlugin)

    assert len(list(target_win.certlog())) == 142
    assert len(list(target_win.certlog.requests())) == 11
    assert len(list(target_win.certlog.request_attributes())) == 26
    assert len(list(target_win.certlog.crls())) == 2
    assert len(list(target_win.certlog.certificates())) == 11
    assert len(list(target_win.certlog.certificate_extensions())) == 92


def test_certlog_plugin_direct() -> None:
    ca_edb = absolute_path("_data/plugins/os/windows/certlog/SEVENKINGDOMS-CA.edb")

    target = Target.open_direct([ca_edb])
    assert len(list(target.certlog())) == 142
    assert len(list(target.certlog.requests())) == 11
    assert len(list(target.certlog.request_attributes())) == 26
    assert len(list(target.certlog.crls())) == 2
    assert len(list(target.certlog.certificates())) == 11
    assert len(list(target.certlog.certificate_extensions())) == 92
