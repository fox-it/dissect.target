from __future__ import annotations

import sys
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def mock_cbc_sdk(monkeypatch: pytest.MonkeyPatch) -> Iterator[MagicMock]:
    with monkeypatch.context() as m:
        # The references to cbc_sdk properties in the cb loader will point to the MagicMock created
        # for the first test function that runs.
        # Thus we need to delete the cb loader module to force it to be reimported when used in a
        # new test so the MagickMock used in the cb module will be the one created for the test
        # function that is running.
        if "dissect.target.loaders.cb" in sys.modules:
            m.delitem(sys.modules, "dissect.target.loaders.cb")

        mock_cbc_sdk = MagicMock()
        m.setitem(sys.modules, "cbc_sdk", mock_cbc_sdk)
        m.setitem(sys.modules, "cbc_sdk.errors", mock_cbc_sdk.errors)
        m.setitem(sys.modules, "cbc_sdk.live_response_api", mock_cbc_sdk.live_response_api)
        m.setitem(sys.modules, "cbc_sdk.platform", mock_cbc_sdk.platform)
        m.setitem(sys.modules, "cbc_sdk.rest_api", mock_cbc_sdk.rest_api)

        yield mock_cbc_sdk


@pytest.fixture
def mock_device(mock_cbc_sdk: MagicMock) -> MagicMock:
    mock_device = MagicMock()
    mock_device.name = "DOMAIN\\workstation"

    mock_cbc_sdk.rest_api.CBCloudAPI.return_value.select.return_value.all.return_value = [mock_device]

    return mock_device


@pytest.fixture
def mock_session(mock_device: MagicMock) -> MagicMock:
    mock_session = MagicMock()
    mock_device.lr_session.return_value = mock_session

    return mock_session


def test_cb_loader(mock_session: MagicMock) -> None:
    from dissect.target.filesystems.cb import CbFilesystem
    from dissect.target.loader import open as loader_open
    from dissect.target.loaders.cb import CbLoader, CbRegistry

    with patch.dict("dissect.target.loader.LOADERS_BY_SCHEME", {"cb": CbLoader}):
        loader = loader_open("cb://workstation@instance")

    assert isinstance(loader, CbLoader)
    assert loader.session is mock_session

    mock_session.session_data = {"drives": ["C:\\"]}

    t = Target()
    loader.map(t)

    assert len(t.filesystems) == 1
    assert isinstance(t.fs.mounts["c:\\"], CbFilesystem)
    assert t.fs.mounts["c:\\"].prefix == "c:\\"

    assert len(t._plugins) == 1
    assert isinstance(t._plugins[0], CbRegistry)


def test_cb_registry(target_bare: Target, mock_session: MagicMock) -> None:
    from dissect.target.loaders.cb import CbRegistry

    mock_session.list_registry_keys_and_values.return_value = {"sub_keys": ["TestKey"]}

    registry = CbRegistry(target_bare, mock_session)

    test_key = registry.key("HKLM\\SYSTEM\\TestKey")
    assert test_key.name == "TestKey"
    assert test_key.path == "HKEY_LOCAL_MACHINE\\SYSTEM\\TestKey"
    assert str(test_key.timestamp) == "1970-01-01 00:00:00+00:00"

    mock_session.list_registry_keys_and_values.return_value = {
        "sub_keys": ["TestSubKey"],
        "values": [
            {
                "registry_name": "TestValue",
                "registry_data": None,
                "registry_type": "pbREG_NONE",
            },
            {
                "registry_name": "TestBinary",
                "registry_data": "7a6f6d67",
                "registry_type": "pbREG_BINARY",
            },
            {
                "registry_name": "TestDword",
                "registry_data": "1768515945",
                "registry_type": "pbREG_DWORD",
            },
            {
                "registry_name": "TestQword",
                "registry_data": "7595718147998050665",
                "registry_type": "pbREG_QWORD",
            },
            {
                "registry_name": "TestMultiString",
                "registry_data": "zomg,bbq,wowzers",
                "registry_type": "pbREG_MULTI_SZ",
            },
            {
                "registry_name": "TestString",
                "registry_data": "boring",
                "registry_type": "pbREG_SZ",
            },
        ],
    }

    assert len(test_key.subkeys()) == 1
    assert test_key.subkey("TestSubKey")
    mock_session.list_registry_keys_and_values.assert_called_with("HKEY_LOCAL_MACHINE\\SYSTEM\\TestKey")

    assert len(test_key.values()) == 6
    test_value = test_key.value("TestValue")
    assert test_value.name == "TestValue"
    assert test_value.value is None
    assert test_value.type == "pbREG_NONE"

    assert test_key.value("TestBinary").value == b"zomg"
    assert test_key.value("TestDword").value == 0x69696969
    assert test_key.value("TestQword").value == 0x6969696969696969
    assert test_key.value("TestMultiString").value == ["zomg", "bbq", "wowzers"]
    assert test_key.value("TestString").value == "boring"
