from dissect.target.plugins.os.windows import clfs
from tests._utils import absolute_path


def test_clfs_plugin(target_win, fs_win):
    data_dir = absolute_path("_data/plugins/os/windows/clfs")

    fs_win.map_dir("windows/system32/config/", data_dir)

    target_win.add_plugin(clfs.ClfsPlugin)

    records = list(target_win.clfs())

    assert len(records) == 24

    expected_stream = "\\Device\\HarddiskVolume3\\wd\\compilerTemp\\BMT.SignCompDB.1lltmqvq.24r\\MetadataEsdGen\\mounted_image\\Windows\\System32\\config\\DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TM.blf"  # noqa: E501
    stream_names = {str(r.stream_name) for r in records}
    assert len(stream_names) == 1
    assert list(stream_names)[0] == expected_stream

    stream_ids = {r.stream_id for r in records}
    assert len(stream_ids) == 1
    assert list(stream_ids)[0] == 0

    expected_container = "DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms"
    container_names = {str(r.container_name) for r in records}
    assert len(container_names) == 1
    assert list(container_names)[0] == expected_container

    container_ids = {r.container_id for r in records}
    assert len(container_ids) == 1
    assert list(container_ids)[0] == 0

    container_sizes = {r.container_size for r in records}
    assert len(container_sizes) == 1
    assert list(container_sizes)[0] == 524288

    expected_first_record_offset = 36976
    first_record_offset = records[0].record_offset
    assert first_record_offset == expected_first_record_offset

    expected_last_record_offset = 3184
    last_record_offset = records[-1].record_offset
    assert last_record_offset == expected_last_record_offset

    expected_first_record_data = bytes.fromhex("000000000000000004010000762f16000519ea11a810000d3aa41ef300000000")
    first_record = records[0].record_data
    assert first_record == expected_first_record_data

    expected_first_block_data = bytes.fromhex(
        """
        04 01 00 00 04 00 00 00
        be 8e 6b c1 61 db ec 11
        a4 ba 00 50 56 ef c5 14
        0d 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 80 02 01 00 00 10
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        """
    )
    first_block_data = records[0].block_data
    assert first_block_data == expected_first_block_data

    expected_last_record_data = bytes.fromhex("000000000000000004010000762f16000519ea11a810000d3aa41ef300000000")
    last_record = records[-1].record_data
    assert last_record == expected_last_record_data

    expected_last_block_data = bytes.fromhex(
        """
        04 01 00 00 04 00 00 00
        e1 b9 29 a6 ea d7 eb 11
        a4 6b 3c 22 fb 13 6b f1
        21 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        00 00 80 02 01 00 00 10
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00
        """
    )
    last_block_data = records[-1].block_data
    assert last_block_data == expected_last_block_data
