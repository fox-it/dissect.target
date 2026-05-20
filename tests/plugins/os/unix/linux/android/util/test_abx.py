from __future__ import annotations

from defusedxml import ElementTree

from dissect.target.plugins.os.unix.linux.android.util.abx import AbxFile
from tests._utils import absolute_path


def test_abx_simple() -> None:
    """Test if we can parse a simple ABX file."""
    file = absolute_path("_data/plugins/os/unix/linux/android/users/userlist.xml")
    abx = AbxFile(file, to_str=True)

    assert ElementTree.tostring(abx.tree.getroot()).decode() == (
        '<users nextSerialNumber="10" version="11" userTypeConfigVersion="0">'
        "<guestRestrictions>"
        '<restrictions no_sms="True" no_install_unknown_sources="True" no_config_wifi="True" no_config_credentials="True" no_outgoing_calls="True" />'  # noqa: E501
        "</guestRestrictions>"
        '<user id="0" />'
        "</users>"
    )


def test_abx_multiple_root_elements() -> None:
    """Test if we can parse an ABX file with multiple root elements."""
    file = absolute_path("_data/plugins/os/unix/linux/android/users/settings_global.xml")
    abx = AbxFile(file, to_str=True)

    assert (
        ElementTree.tostring(abx.tree.getroot()).decode()
        == absolute_path("_data/plugins/os/unix/linux/android/users/settings_global.dec").read_text()
    )
