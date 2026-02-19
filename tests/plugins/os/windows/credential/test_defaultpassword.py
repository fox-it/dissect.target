from __future__ import annotations

from typing import TYPE_CHECKING
from unittest import mock

import pytest

from dissect.target.plugins.os.windows.credential.defaultpassword import DefaultPasswordPlugin
from dissect.target.plugins.os.windows.lsa import LSAPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("reg_key", "reg_value", "expected_value"),
    [
        pytest.param(
            "DefaultPassword",
            bytes.fromhex("00000000000000000000000000000000d41d8cd98f00b204e9800998ecf8427e"),
            "d41d8cd98f00b204e9800998ecf8427e",
            id="small",
        ),
        pytest.param(
            "DefaultPassword_OldVal",
            bytes.fromhex(
                "10000000000000000000000000000000700061007300730077006f0072006400d41d8cd98f00b204e9800998ecf8427e"
            ),
            "password",
            id="regular",
        ),
        pytest.param(
            "DefaultPassword",
            bytes.fromhex("10000000000000000000000000000000700061007300730077006f0072006400"),
            "password",
            id="no-trailer",
        ),
    ],
)
def test_windows_credential_defaultpassword_lsa(
    target_win: Target, reg_key: str, reg_value: bytes, expected_value: str
) -> None:
    """Test if we can parse a DefaultPassword LSA entry."""

    with mock.patch(
        "dissect.target.plugins.os.windows.lsa.LSAPlugin._secrets",
        new_callable=mock.PropertyMock,
        return_value={reg_key: reg_value},
    ):
        target_win.add_plugin(LSAPlugin, check_compatible=False)
        target_win.add_plugin(DefaultPasswordPlugin)

        records = list(target_win.credential.defaultpassword())

        assert len(records) == 1

        assert records[0].default_password == expected_value
        assert records[0].source == f"HKLM\\SECURITY\\Policy\\Secrets\\{reg_key}"
