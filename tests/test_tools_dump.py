import json
import pathlib

import pytest
from unittest.mock import patch

from dissect.target.plugins.os.windows import iis, amcache
from dissect.target.tools.dump import run, state, utils

from ._utils import absolute_path


@pytest.fixture
def target_win_iis_amcache(target_win, fs_win):
    config_path = absolute_path("data/iis-applicationHost-iis.config")
    data_dir = absolute_path("data/iis-logs-iis")

    fs_win.map_file("windows/system32/inetsrv/config/applicationHost.config", config_path)
    fs_win.map_dir("Users/John/iis-logs", data_dir)

    target_win.add_plugin(iis.IISLogsPlugin)

    amcache_file = absolute_path("data/amcache-new.hve")
    fs_win.map_file("windows/appcompat/programs/amcache.hve", amcache_file)

    target_win.add_plugin(amcache.AmcachePlugin)
    return target_win


@pytest.mark.parametrize(
    "serialization_name,compression_name",
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
    compression_name,
    serialization_name,
    target_win_iis_amcache,
    tmpdir_name,
):
    def mock_get_targets(_):
        yield target_win_iis_amcache

    def mock_log_progress(stream):
        count = 0
        for element in stream:
            yield element
            count += 1
        assert count == 128

    with patch("dissect.target.tools.dump.run.get_targets", new=mock_get_targets), patch(
        "dissect.target.tools.dump.run.log_progress", new=mock_log_progress
    ):
        output_dir = pathlib.Path(tmpdir_name)

        serialization = utils.Serialization(serialization_name)
        compression = utils.Compression(compression_name)

        functions = ["iis.logs", "amcache.applications"]

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

        with open(state_path, "r") as f:
            state_blob = json.loads(f.read())

        assert state_blob["compression"] == compression_name
        assert state_blob["serialization"] == serialization_name
        assert state_blob["target_paths"] == ["dummy"]
        assert state_blob["functions"] == functions

        sink_blobs = state_blob["sinks"]

        assert len(sink_blobs) == 2
        assert {s["func"] for s in sink_blobs} == set(functions)

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
def test_execute_pipeline_limited(limit, target_win_iis_amcache, tmpdir_name):
    def mock_get_targets(_):
        yield target_win_iis_amcache

    def mock_log_progress(stream):
        count = 0
        for element in stream:
            yield element
            count += 1

        if limit:
            assert count == limit
        else:
            assert count == 128

    with patch("dissect.target.tools.dump.run.get_targets", new=mock_get_targets), patch(
        "dissect.target.tools.dump.run.log_progress", new=mock_log_progress
    ):
        output_dir = pathlib.Path(tmpdir_name)

        functions = ["iis.logs", "amcache.applications"]

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

        with open(state_path, "r") as f:
            state_blob = json.loads(f.read())

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
            assert {s["func"] for s in sink_blobs} == set(functions)

            amcache_sink_blob = next(s for s in state_blob["sinks"] if s["func"] == "amcache.applications")

            if limit:
                assert amcache_sink_blob["record_count"] == limit - 10
                assert amcache_sink_blob["is_dirty"]
            else:
                assert amcache_sink_blob["record_count"] == 118
                assert not amcache_sink_blob["is_dirty"]
