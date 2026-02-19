from __future__ import annotations

import json

import pytest

from dissect.target.tools.info import main as target_info
from tests._utils import absolute_path


@pytest.mark.parametrize(
    ("output_type", "options"),
    [("json", ["-j"]), ("json", ["-J", "-L", "tar"]), ("record", ["-r", "-s"])],
)
def test_target_info(
    capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch, output_type: str, options: list
) -> None:
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-info", *options, str(absolute_path("_data/tools/info/image.tar"))])

        target_info()
        stdout, stderr = capsys.readouterr()

        assert "error" not in stderr

        if output_type == "json":
            assert json.loads(stdout) == {
                "disks": [],
                "volumes": [],
                "children": [],
                "hostname": "ubuntu",
                "domain": None,
                "ips": ["1.2.3.4"],
                "os_family": "linux",
                "os_version": "Ubuntu 22.04.4 LTS (Jammy Jellyfish)",
                "architecture": None,
                "language": [],
                "timezone": "Europe/Amsterdam",
                "install_date": "2024-07-02 12:00:56+00:00",
                "last_activity": None,
                "mounts": [{"fs": "virtual", "path": "/"}],
            }

        elif output_type == "record":
            assert (
                stdout
                == "<target/info hostname='ubuntu' domain=None last_activity=None install_date=2024-07-02 12:00:56+00:00 ips=[net.ipaddress('1.2.3.4')] os_family='linux' os_version='Ubuntu 22.04.4 LTS (Jammy Jellyfish)' architecture=None language=[] timezone='Europe/Amsterdam' disks=[] volumes=[] mounts=[\"{'fs': 'virtual', 'path': '/'}\"] children=[]>\n"  # noqa: E501
            )

        else:
            raise ValueError("unknown output_type %s", output_type)


@pytest.mark.parametrize(
    ("output_type", "options"),
    [("json", ["-j"]), ("json", ["-J", "-L", "tar"]), ("record", ["-r", "-s"])],
)
def test_target_info_with_exception(
    capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch, output_type: str, options: list
) -> None:
    """Test target-info on a target that raises exceptions in some properties."""
    with monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            ["target-info", *options, str(absolute_path("_data/loaders/acquire/test-windows-fs-c-absolute.tar"))],
        )

        target_info()
        stdout, stderr = capsys.readouterr()

        assert "error" not in stderr

        if output_type == "json":
            assert json.loads(stdout) == {
                "disks": [],
                "volumes": [],
                "children": [],
                "hostname": None,
                "domain": None,
                "ips": None,
                "os_family": "windows",
                "os_version": None,
                "architecture": None,
                "language": None,
                "timezone": None,
                "install_date": None,
                "last_activity": None,
                "mounts": [{"fs": "virtual", "path": "c:"}, {"fs": "virtual", "path": "sysvol"}],
            }

        elif output_type == "record":
            assert (
                stdout
                == "<target/info hostname=None domain=None last_activity=None install_date=None ips=[] os_family='windows' os_version=None architecture=None language=[] timezone=None disks=[] volumes=[] mounts=[\"{'fs': 'virtual', 'path': 'c:'}\", \"{'fs': 'virtual', 'path': 'sysvol'}\"] children=[]>\n"  # noqa: E501
            )

        else:
            raise ValueError("unknown output_type %s", output_type)
