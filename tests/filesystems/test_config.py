from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from dissect.target.filesystems.config import (
    ConfigurationEntry,
    ConfigurationFilesystem,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def etc_directory(tmp_path: Path, fs_unix: VirtualFilesystem) -> VirtualFilesystem:
    etc_path = tmp_path.joinpath("etc/")
    etc_path.joinpath("new/path").mkdir(parents=True, exist_ok=True)
    etc_path.joinpath("new/config").mkdir(parents=True, exist_ok=True)
    etc_path.joinpath("new/path/config").write_text(Path(absolute_path("_data/helpers/configutil/config")).read_text())
    fs_unix.map_dir("/etc", etc_path)

    return fs_unix


@pytest.fixture
def mapped_file(test_file: str, fs_unix: VirtualFilesystem) -> VirtualFilesystem:
    local_path = Path(absolute_path(test_file))
    file_name = f"/etc/{local_path.name}"
    fs_unix.map_file(file_name, local_path.absolute())
    return "/" + local_path.name


@pytest.mark.parametrize(
    ("test_file", "expected_output"),
    [
        (
            "_data/helpers/configutil/hosts",
            {
                "127.0.0.1": "localhost",
                "::1": "localhost",
                "127.0.1.1": "pop-os.localdomain pop-os",
            },
        ),
        (
            "_data/helpers/configutil/hosts.allow",
            {"ALL": ["LOCAL @some_netgroup", ".foobar.edu EXCEPT terminalserver.foobar.edu"]},
        ),
        (
            "_data/helpers/configutil/hosts.deny",
            {"ALL": "PARANOID", "ALL EXCEPT in.fingerd": "other.host.name, .other.domain"},
        ),
        (
            "_data/helpers/configutil/resolv.conf",
            {"nameserver": "127.0.0.53", "options": "edns0", "search": "local"},
        ),
        (
            "_data/helpers/configutil/sshd_config",
            {
                "HostKey": [f"__PROGRAMDATA__/ssh/ssh_host_{key}_key" for key in ["rsa", "dsa", "ecdsa", "ed25519"]],
                "AuthorizedKeysFile": ".ssh/authorized_keys",
                "Subsystem": "sftp sftp-server.exe",
                "Match Group administrators": {
                    "AuthorizedKeysFile": "__PROGRAMDATA__/ssh/administrators_authorized_keys"
                },
                "Match User anoncvs": {
                    "AllowTcpForwarding": "no",
                    "PermitTTY": "no",
                    "ForceCommand": "cvs server",
                },
            },
        ),
        (
            "_data/helpers/configutil/test.xml",
            {
                "Server": {
                    "attributes": {"port": "8005", "shutdown": "SHUTDOWN"},
                    "nodes": {
                        "Listener": {
                            "attributes": {"className": "org.apache.catalina.core.JasperListener1"},
                            "text": "a",
                        },
                        "Listener-2": {
                            "attributes": {"className": "org.apache.catalina.core.JasperListener2"},
                            "text": "b",
                        },
                        "Service": {
                            "attributes": {"name": "Catalina"},
                            "nodes": {
                                "Connector": {
                                    "attributes": {
                                        "port": "8080",
                                        "protocol": "HTTP/1.1",
                                        "connectionTimeout": "20000",
                                        "redirectPort": "8443",
                                    },
                                },
                                "Engine": {
                                    "attributes": {"name": "Catalina", "defaultHost": "localhost"},
                                    "nodes": {
                                        "Host": {
                                            "attributes": {
                                                "name": "localhost",
                                                "appBase": "webapps",
                                                "unpackWARs": "true",
                                                "autoDeploy": "true",
                                            },
                                            "nodes": {
                                                "Valve": {
                                                    "attributes": {
                                                        "className": "org.apache.catalina.valves.AccessLogValve",
                                                        "directory": "logs",
                                                        "prefix": "localhost_access_log.",
                                                        "suffix": ".txt",
                                                        "pattern": "%h %l %u %t s",
                                                    },
                                                }
                                            },
                                        }
                                    },
                                },
                            },
                        },
                    },
                },
            },
        ),
    ],
)
def test_parse_file_input(target_unix: Target, mapped_file: str, expected_output: dict) -> None:
    config_filesystem = ConfigurationFilesystem(target_unix, "/etc")
    entry: ConfigurationEntry = config_filesystem.get(mapped_file)
    check_dictionary(expected_output, entry.parser_items)


def check_dictionary(expected_dict: dict, data_dict: dict) -> None:
    for key, value in expected_dict.items():
        if info_value := data_dict.get(key):
            check_value(value, info_value)
        else:
            raise AssertionError(f"Key {key!r} was not found in parser_items.")


def check_value(expected_value: Any, value: Any) -> None:
    assert type(expected_value) is type(value), "The types of the values are not the same"
    if isinstance(expected_value, list):
        # Check if all elements of the expected value are in value
        assert all(val in value for val in expected_value)

    if isinstance(expected_value, dict):
        check_dictionary(expected_value, value)


def test_unix_registry(target_unix: Target, etc_directory: VirtualFilesystem) -> None:
    config_fs = ConfigurationFilesystem(target_unix, "/etc")
    config_path = list(config_fs.get("/").iterdir())

    assert config_path == ["new"]
    assert sorted(config_fs.get("/new").iterdir()) == ["config", "path"]
    assert isinstance(config_fs.get("/new/path/config"), ConfigurationEntry)


def test_parse_functions(target_unix: Target, etc_directory: VirtualFilesystem) -> None:
    config_fs = ConfigurationFilesystem(target_unix, "/etc")
    entry: ConfigurationEntry = config_fs.get("/new/path/config", collapse=True, separator=(r"\s",))

    assert entry["help"] == "you"
    assert entry["test"] == "you"

    entry = config_fs.get("/new/path/config", collapse={"help"}, separator=(r"\s",))

    assert entry["help"] == "you"
    assert entry["test"] == ["me", "you"]
