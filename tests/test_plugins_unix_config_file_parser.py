from pathlib import Path
from typing import Any

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.config import (
    ConfigurationEntry,
    ConfigurationFilesystem,
)

from ._utils import absolute_path


@pytest.fixture
def mapped_file(test_file: str, fs_unix: VirtualFilesystem) -> VirtualFilesystem:
    local_path = Path(absolute_path(test_file))
    file_name = f"/etc/{local_path.name}"
    fs_unix.map_file(file_name, local_path.absolute())
    return local_path.name


@pytest.mark.parametrize(
    "test_file, expected_output",
    [
        (
            "data/config_tree/hosts",
            {
                "127.0.0.1": "localhost",
                "::1": "localhost",
                "127.0.1.1": "pop-os.localdomain pop-os",
            },
        ),
        (
            "data/config_tree/hosts.allow",
            {"ALL": ["LOCAL @some_netgroup", ".foobar.edu EXCEPT terminalserver.foobar.edu"]},
        ),
        (
            "data/config_tree/hosts.deny",
            {"ALL": "PARANOID", "ALL EXCEPT in.fingerd": "other.host.name, .other.domain"},
        ),
        (
            "data/config_tree/resolv.conf",
            {"nameserver": "127.0.0.53", "options": "edns0", "search": "local"},
        ),
        (
            "data/config_tree/sshd_config",
            {
                "HostKey": [f"__PROGRAMDATA__/ssh/ssh_host_{key}_key" for key in ["rsa", "dsa", "ecdsa", "ed25519"]],
                "AuthorizedKeysFile": ".ssh/authorized_keys",
                "Subsystem": "sftp sftp-server.exe",
                "Match": {
                    "Group administrators": {
                        "AuthorizedKeysFile": "__PROGRAMDATA__/ssh/administrators_authorized_keys",
                    }
                },
            },
        ),
    ],
)
def test_hosts_file(target_unix: Target, mapped_file: str, expected_output: dict):
    config_filesystem = ConfigurationFilesystem(target_unix)
    entry: ConfigurationEntry = config_filesystem.get(mapped_file)
    check_dictionary(expected_output, entry.parser_items)


def check_dictionary(expected_dict: dict, data_dict: dict):
    for key, value in expected_dict.items():
        if info_value := data_dict.get(key):
            check_value(value, info_value)
        else:
            raise AssertionError(f"Key {key!r} was not found in parser_items.")


def check_value(expected_value: Any, value: Any):
    assert type(expected_value) is type(value), "The types of the values are not the same"
    if isinstance(expected_value, list):
        # Check if all elements of the expected value are in value
        assert all(val in value for val in expected_value)

    if isinstance(expected_value, dict):
        check_dictionary(expected_value, value)
