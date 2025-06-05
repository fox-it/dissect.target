from __future__ import annotations

import json
import pathlib
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest

from dissect.target.plugins.apps.webserver import iis
from dissect.target.plugins.os.windows import amcache
from dissect.target.tools.dump import run, state, utils
from dissect.target.tools.dump.run import main as target_dump
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_win_iis_amcache(target_win_tzinfo: Target, fs_win: VirtualFilesystem) -> iis.Target:
    config_path = absolute_path("_data/plugins/apps/webserver/iis/iis-applicationHost-iis.config")
    data_dir = absolute_path("_data/plugins/apps/webserver/iis/iis-logs-iis")

    fs_win.map_file("windows/system32/inetsrv/config/applicationHost.config", config_path)
    fs_win.map_dir("Users/John/iis-logs", data_dir)

    target_win_tzinfo.add_plugin(iis.IISLogsPlugin)

    amcache_file = absolute_path("_data/plugins/os/windows/amcache/amcache-new.hve")
    fs_win.map_file("windows/appcompat/programs/amcache.hve", amcache_file)

    target_win_tzinfo.add_plugin(amcache.AmcachePlugin)
    return target_win_tzinfo


@pytest.mark.parametrize(
    ("serialization_name", "compression_name"),
    [
        ("jsonlines", "gzip"),
        ("jsonlines", "bzip2"),
        ("jsonlines", None),
        ("msgpack", "gzip"),
        ("msgpack", "bzip2"),
        ("msgpack", None),
    ],
)
def test_execute_pipeline(
    serialization_name: str,
    compression_name: str | None,
    target_win_iis_amcache: Target,
    tmp_path: pathlib.Path,
) -> None:
    def mock_get_targets(targets: list[str]) -> Iterator[Target]:
        yield target_win_iis_amcache

    def mock_log_progress(stream: Iterable[Any]) -> Iterator[Any]:
        count = 0
        for element in stream:
            yield element
            count += 1
        assert count == 128

    with (
        patch("dissect.target.tools.dump.run.get_targets", new=mock_get_targets),
        patch("dissect.target.tools.dump.run.log_progress", new=mock_log_progress),
    ):
        output_dir = tmp_path / "output"

        serialization = utils.Serialization(serialization_name)
        compression = utils.Compression(compression_name)

        functions = "iis.logs,amcache.applications"

        run.execute_pipeline(
            targets=["dummy"],
            functions=functions,
            output_dir=output_dir,
            serialization=serialization,
            compression=compression,
        )

        target_name = target_win_iis_amcache.name

        # verify that iis records are in place

        assert (output_dir / target_name / "iis").exists()

        serialization_ext = utils.SERIALIZERS[serialization]["ext"]
        compression_ext = utils.COMPRESSION_TO_EXT[compression]

        iis_sink_filename = f"filesystem_windows_iis_logs.{serialization_ext}"
        if compression_ext:
            iis_sink_filename += f".{compression_ext}"

        assert (output_dir / target_name / "iis" / iis_sink_filename).exists()

        # verify that amcache.applications records are in place

        assert (output_dir / target_name / "amcache").exists()

        amcache_sink_filename = f"windows_appcompat_InventoryApplication.{serialization_ext}"
        if compression_ext:
            amcache_sink_filename += f".{compression_ext}"

        assert (output_dir / target_name / "amcache" / amcache_sink_filename).exists()

        # verify that serialized state is in place
        state_path = output_dir / state.STATE_FILE_NAME
        assert state_path.exists()

        state_blob = json.loads(state_path.read_text())

        assert state_blob["compression"] == compression_name
        assert state_blob["serialization"] == serialization_name
        assert state_blob["target_paths"] == ["dummy"]
        assert state_blob["functions"] == functions

        sink_blobs = state_blob["sinks"]

        assert len(sink_blobs) == 2
        assert {s["func"] for s in sink_blobs} == set(functions.split(","))

        assert all(s["is_dirty"] is False for s in sink_blobs)

        # validate iis sink blob
        iis_sink_blob = next(s for s in state_blob["sinks"] if s["func"] == "iis.logs")
        assert iis_sink_blob["record_count"] == 10
        assert iis_sink_blob["target_path"] == str(target_win_iis_amcache.path)
        assert iis_sink_blob["path"] == str(pathlib.Path(target_name) / "iis" / iis_sink_filename)

        # validate amcache sink blob
        amcache_sink_blob = next(s for s in state_blob["sinks"] if s["func"] == "amcache.applications")
        assert amcache_sink_blob["record_count"] == 118
        assert amcache_sink_blob["target_path"] == str(target_win_iis_amcache.path)
        assert amcache_sink_blob["path"] == str(pathlib.Path(target_name) / "amcache" / amcache_sink_filename)


@pytest.mark.parametrize("limit", [5, 15, None])
def test_execute_pipeline_limited(limit: int | None, target_win_iis_amcache: Target, tmp_path: pathlib.Path) -> None:
    def mock_get_targets(targets: list[str]) -> Iterator[Target]:
        yield target_win_iis_amcache

    def mock_log_progress(stream: Iterable[Any]) -> Iterator[Any]:
        count = 0
        for element in stream:
            yield element
            count += 1

        if limit:
            assert count == limit
        else:
            assert count == 128

    with (
        patch("dissect.target.tools.dump.run.get_targets", new=mock_get_targets),
        patch("dissect.target.tools.dump.run.log_progress", new=mock_log_progress),
    ):
        output_dir = tmp_path / "output"

        functions = "iis.logs,amcache.applications"

        run.execute_pipeline(
            targets=["dummy"],
            functions=functions,
            output_dir=output_dir,
            serialization=utils.Serialization.JSONLINES,
            limit=limit,
        )

        target_name = target_win_iis_amcache.name

        # verify that iis records are in place
        assert (output_dir / target_name / "iis").exists()

        serialization_ext = utils.SERIALIZERS[utils.Serialization.JSONLINES]["ext"]
        iis_sink_filename = f"filesystem_windows_iis_logs.{serialization_ext}"

        assert (output_dir / target_name / "iis" / iis_sink_filename).exists()

        # verify that serialized state is in place
        state_path = output_dir / state.STATE_FILE_NAME
        assert state_path.exists()

        state_blob = json.loads(state_path.read_text())

        assert state_blob["compression"] is None
        sink_blobs = state_blob["sinks"]

        iis_sink_blob = next(s for s in state_blob["sinks"] if s["func"] == "iis.logs")

        # verify that amcache.applications records are absent if `limit` is smaller/equal than 10 (the number
        # of iis records), and present if `limit` is `None` or larger than 10.
        if limit and limit <= 10:
            assert not (output_dir / target_name / "amcache").exists()

            assert len(sink_blobs) == 1
            assert {s["func"] for s in sink_blobs} == {"iis.logs"}

            assert iis_sink_blob["record_count"] == limit
            if limit < 10:
                # if limit cuts the record stream, the sink should be marked as dirty
                assert iis_sink_blob["is_dirty"]
            else:
                assert not iis_sink_blob["is_dirty"]

        else:
            assert (output_dir / target_name / "amcache").exists()
            amcache_sink_filename = f"windows_appcompat_InventoryApplication.{serialization_ext}"
            assert (output_dir / target_name / "amcache" / amcache_sink_filename).exists()

            assert len(sink_blobs) == 2
            assert {s["func"] for s in sink_blobs} == set(functions.split(","))

            amcache_sink_blob = next(s for s in state_blob["sinks"] if s["func"] == "amcache.applications")

            if limit:
                assert amcache_sink_blob["record_count"] == limit - 10
                assert amcache_sink_blob["is_dirty"]
            else:
                assert amcache_sink_blob["record_count"] == 118
                assert not amcache_sink_blob["is_dirty"]


def test_dump(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    with monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            [
                "target-dump",
                "-f",
                "walkfs",
                "tests/_data/loaders/tar/test-archive.tar.gz",
                "-o",
                str(tmp_path),
            ],
        )

        target_dump()

        assert tmp_path.joinpath("target-dump.state.json").exists()

        entry = tmp_path.joinpath("test-archive.tar.gz/walkfs/filesystem_entry.jsonl")
        assert entry.exists()
        assert "test-file.txt" in entry.read_text()
