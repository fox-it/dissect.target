from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flow.record.fieldtypes import digest

from dissect.target.plugins.os.windows.catroot import CatrootPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("filename", "hashes", "file_hints", "len_results"),
    [
        pytest.param(
            "catroot_package_name.cat",
            [
                "18d4711ffaf619d81c76b9a2375888316cbce6cfde6298b7e2d7165028281cde",
                "9333e6100ea011d73bd6d927237d93c284424042d8e339e7bec58e958cf1b18a",
                "d6bffeb5833fc17ddc441459f4a90f866a270d10b2261f1775f303ea1e600ede",
            ],
            ["Microsoft-Windows-PhotoBasic-WOW64-merged-Package"],
            3,
            id="PackageName",
        ),
        pytest.param(
            "catroot_package_name_2.cat",
            [
                "9504d1e72c0276088ba53d493b869d9dd1da253852823b4f44ea05d2c59e488e",
            ],
            ["Microsoft-Windows-Printing-PrintToPDFServices-Package"],
            1,
            id="PackageName2",
        ),
        pytest.param(
            "catroot_file_hint.cat",
            [
                "0469496b538e68ae97b6dc856a16e272830d8b0f8c978254e19226f5a2cdb71e",
                "0a3b6d06699313dc2b4fb2ae1e677c416408ade6a1ca022395b3cd92764ddd5d",
                "1a4ced5ac0b485f859584743042ff6eef68329b95ae8979b192e9ed46dc4a5cc",
                "32e8250fba4d4d24692cca4fa91dfd6659ab811ff37fd071f7875c6178888ba7",
                "35b07ee2cf53351917b966283fedebb58ccae21df358223301ba77577c186136",
            ],
            [
                "msil_multipoint-wms.coll..lecontrol.resources_31bf3856ad364e35_10.0.19041.1_en-us_be33ff08e678d0dc\\Wms.CollapsibleControl.Resources.dll",
                "msil_multipoint-wmsmanager.resources_31bf3856ad364e35_10.0.19041.1_en-us_b4f3be8d3d296eb4\\WmsManager.Resources.dll",
                "msil_multipoint-wms.alertsview.resources_31bf3856ad364e35_10.0.19041.1_en-us_7a57dedfa22c1a6d\\Wms.AlertsView.Resources.dll",
                "msil_multipoint-wmsadminuilibrary.resources_31bf3856ad364e35_10.0.19041.1_en-us_47cfbfac3d8bbe69\\WmsAdminUILibrary.Resources.dll",
                "msil_multipoint-wms.dash..addintabs.resources_31bf3856ad364e35_10.0.19041.1_en-us_f6c7cebefb0b4d85\\Wms.Dashboard.AddinTabs.Resources.dll",
                "msil_multipoint-wmswssgcommon.resources_31bf3856ad364e35_10.0.19041.1_en-us_b7261118c0f1fbfe\\WmsWssgCommon.Resources.dll",
                "msil_multipoint-wms.skuresources.resources_31bf3856ad364e35_10.0.19041.1_en-us_fc4901fade485b61\\Wms.SkuResources.Resources.dll",
                "msil_multipoint-wmsusertab.resources_31bf3856ad364e35_10.0.19041.1_en-us_a64149851e198a87\\WmsUserTab.Resources.dll",
                "msil_multipoint-wmssystemtab.resources_31bf3856ad364e35_10.0.19041.1_en-us_38e614cdb422ddf1\\WmsSystemTab.Resources.dll",
                "msil_multipoint-wms.mmstools.resources_31bf3856ad364e35_10.0.19041.1_en-us_94ce42426fe482ef\\Wms.MMSTools.Resources.dll",
                "msil_multipoint-wmsstatustab.resources_31bf3856ad364e35_10.0.19041.1_en-us_8c4e51c6a0a9be12\\WmsStatusTab.Resources.dll",
                "msil_multipoint-wmsdashboard.resources_31bf3856ad364e35_10.0.19041.1_en-us_f7e7f4de797fc24f\\WmsDashboard.Resources.dll",
                "msil_multipoint-wms.admincommon.resources_31bf3856ad364e35_10.0.19041.1_en-us_7c8a2d4f818abac3\\Wms.AdminCommon.Resources.dll",
                "msil_multipoint-wms.dashboard.forms.resources_31bf3856ad364e35_10.0.19041.1_en-us_3f56c777fba2ec12\\Wms.Dashboard.Forms.Resources.dll",
                "msil_multipoint-wms.dashboardcommon.resources_31bf3856ad364e35_10.0.19041.1_en-us_3c11dbfdda22a912\\Wms.DashboardCommon.Resources.dll",
            ],
            34,
            id="FileHint",
        ),
    ],
)
def test_catroot_files(
    target_win: Target,
    fs_win: VirtualFilesystem,
    filename: str,
    hashes: list[str],
    file_hints: list[str],
    len_results: int,
) -> None:
    catroot_file = absolute_path(f"_data/plugins/os/windows/catroot/{filename}")
    file_location = f"\\windows\\system32\\catroot\\test\\{filename}"
    fs_win.map_file(
        file_location,
        catroot_file,
    )

    target_win.add_plugin(CatrootPlugin)

    records = list(target_win.catroot.files())

    assert len(records) == len_results

    sorted_file_hints = sorted(file_hints)
    # Make sure the order is constant by sorting on digest
    for cat_hash, record in zip(sorted(hashes), sorted(records, key=lambda r: r.digest.sha256)):
        assert str(record.source) == "sysvol" + file_location
        assert record.catroot_name == filename
        assert sorted(record.hints) == sorted_file_hints
        assert record.digest.sha256 == cat_hash


def test_catroot_catdb(target_win: Target, fs_win: VirtualFilesystem) -> None:
    catroot_file = absolute_path("_data/plugins/os/windows/catroot/catdb")
    fs_win.map_file("windows/system32/catroot2/{ID}/catdb", catroot_file)

    target_win.add_plugin(CatrootPlugin)

    records = list(target_win.catroot.catdb())

    hashes = [
        digest({"sha256": "083b9b717253f48ac314e6aa92b88fa775d194420a55f1b3e291ceffbff2377a"}),
        digest({"sha1": "fe71c1d4efa330b807ce00dc0b5055f8ab95eb02"}),
    ]

    assert len(records) == 2

    # Make sure the order is constant by sorting on digest
    for expected_digest, record in zip(
        sorted(hashes, key=lambda d: d.sha1 or d.sha256),
        sorted(records, key=lambda r: r.digest.sha1 or r.digest.sha256),
    ):
        assert record.catroot_name == "Containers-ApplicationGuard-Package~31bf3856ad364e35~amd64~~10.0.19041.1288.cat"
        assert record.source == "sysvol\\windows\\system32\\catroot2\\{ID}\\catdb"
        assert record.hints == []
        # No direct comparison available, but representation comparison suffices.
        assert str(expected_digest) == str(record.digest)
