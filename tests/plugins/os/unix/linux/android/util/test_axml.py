from __future__ import annotations

from dissect.target.plugins.os.unix.linux.android.util.axml import AXmlFile
from tests._utils import absolute_path


def test_android_manifest() -> None:
    """Test if we can parse a compiled AXML AndroidManifest.xml file."""
    path = absolute_path("_data/plugins/os/unix/linux/android/applications/AndroidManifest.xml")
    axml = AXmlFile(path)
    et = axml.tree
    ns = r"{http://schemas.android.com/apk/res/android}"

    assert (el := et.find("."))
    assert el.tag == "manifest"
    assert el.attrib["package"] == "dev.serwin.AnarchRE"
    assert el.attrib[f"{ns}versionCode"] == "3"

    assert [e.tag for e in el.findall("./")] == [
        "uses-sdk",
        "uses-feature",
        "uses-feature",
        "uses-feature",
        "uses-feature",
        "uses-feature",
        "uses-feature",
        "uses-permission",
        "application",
    ]
