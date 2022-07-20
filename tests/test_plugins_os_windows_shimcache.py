import binascii
from io import BytesIO
from unittest.mock import Mock, mock_open, patch

import pytest
from dissect.util.ts import wintimestamp

from dissect.target.plugins.os.windows.regf.shimcache import (
    MAGIC_NT52,
    MAGIC_NT61,
    MAGIC_WIN10,
    MAGIC_WIN81,
    SHIMCACHE_WIN_TYPE,
    TYPE_VARIATIONS,
    CRCMismatchException,
    ShimCache,
    ShimcachePlugin,
    c_shim,
)

TEST_ARGUMENTS = {
    SHIMCACHE_WIN_TYPE.VERSION_WIN81_NO_HEADER: {"path_len": 1},
    SHIMCACHE_WIN_TYPE.VERSION_WIN81: {"ts": 0, "pkg_len": 0, "pkg": "", "path_len": 0},
}


def create_header_bytes(magic: int, position=0, length=0x100):
    if position > length - 4:
        raise ValueError("total header bytes would be larger than length.")

    result_array = b"\x00" * length
    output_array = result_array[0:position] + magic.to_bytes(4, "little") + result_array[position + 4 :]
    return BytesIO(output_array)


@pytest.fixture
def mocked_shimcache():
    with patch.object(ShimCache, "identify"):
        shimcache = ShimCache(fh=BytesIO(b""), ntversion="", noheader=False)
    return shimcache


@pytest.fixture(params=[True, False])
def crc_check(request):
    return request.param


@pytest.fixture
def mocked_nt61_file(version, pathname):
    winnt_variations = TYPE_VARIATIONS.get(version)

    nt_header = winnt_variations.get("header")
    nt_header_data = nt_header(magic=0, num_entries=1).dumps()
    nt_entry_header = winnt_variations.get("header_function")
    nt_entry_header_data = nt_entry_header(nt_header_data)().dumps()

    open_file = mock_open().return_value
    open_file.read.side_effect = [
        nt_header_data,
        nt_entry_header_data,
        pathname,
    ]

    return winnt_variations, open_file


@pytest.fixture
def created_header_win8plus(crc_check, version):
    variations = TYPE_VARIATIONS.get(version)
    entry_header, data_header = variations.get("headers")

    additional_kwargs = TEST_ARGUMENTS.get(version, {})

    data = data_header(path="", **additional_kwargs).dumps()
    entry = entry_header()

    if hasattr(entry, "data"):
        entry.len = len(data)
        entry.data = data

    if crc_check:
        entry.crc = binascii.crc32(data)

    mocked_file = mock_open(read_data=entry.dumps())
    return variations, mocked_file


@pytest.fixture(params=[0, 1])
def offset(request):
    return request.param


@pytest.fixture
def mocked_nt52_file(offset, pathname):
    winnt_variations = TYPE_VARIATIONS.get(SHIMCACHE_WIN_TYPE.VERSION_NT52)

    nt_header = winnt_variations.get("header")
    nt_header_data = nt_header(magic=0, num_entries=1).dumps()
    nt_entry_header = winnt_variations.get("header_function")
    nt_entry_header_data = nt_entry_header(b"\x00" * 32)(_padding=offset).dumps()

    length = len(c_shim.NT52_ENTRY_32 if offset else c_shim.NT52_ENTRY_64)

    open_file = mock_open().return_value
    open_file.read.side_effect = [
        nt_header_data,
        nt_entry_header_data[: len(c_shim.NT52_ENTRY_32)],
        nt_entry_header_data[:length],
        pathname,
    ]

    return winnt_variations, open_file


@pytest.mark.parametrize("shimcache_error", [NotImplementedError, EOFError])
def test_shimcache_plugin_initialize(target_win, shimcache_error):

    shimcache = ShimcachePlugin(target_win)
    mocked_registry_keys = Mock()
    target_win.registry.keys = Mock(return_value=[mocked_registry_keys])
    mocked_registry_keys.value.return_value.value = b"hello_world"

    with patch(ShimCache.__module__, side_effect=[shimcache_error]):
        assert [] == list(shimcache.shimcache())


@pytest.mark.parametrize(
    "file_data, ntversion, expected_value",
    [
        (create_header_bytes(MAGIC_NT52), "6.3", SHIMCACHE_WIN_TYPE.VERSION_NT52),
        (create_header_bytes(MAGIC_NT61), "6.3", SHIMCACHE_WIN_TYPE.VERSION_NT61),
        (create_header_bytes(MAGIC_WIN81), "6.3", SHIMCACHE_WIN_TYPE.VERSION_WIN81_NO_HEADER),
        (create_header_bytes(MAGIC_WIN81, 0x80, 0x84), "6.3", SHIMCACHE_WIN_TYPE.VERSION_WIN81),
        (create_header_bytes(MAGIC_WIN10, 0x30, 0x34), "6.3", SHIMCACHE_WIN_TYPE.VERSION_WIN10),
        (create_header_bytes(MAGIC_WIN10, 0x34, 0x38), "6.3", SHIMCACHE_WIN_TYPE.VERSION_WIN10_CREATORS),
    ],
)
def test_shimcache_identify(mocked_shimcache, file_data, ntversion, expected_value):
    mocked_shimcache.fh = file_data
    mocked_shimcache.ntversion = ntversion
    assert mocked_shimcache.identify() == expected_value


@pytest.mark.parametrize(
    "file_data, ntversion, no_header, expected_value",
    [
        (create_header_bytes(0), "6.3", False, SHIMCACHE_WIN_TYPE.VERSION_WIN81),
        (create_header_bytes(0), "6.3", True, SHIMCACHE_WIN_TYPE.VERSION_WIN81_NO_HEADER),
        (create_header_bytes(0), None, False, NotImplementedError),
        (create_header_bytes(MAGIC_WIN81), None, False, NotImplementedError),
        (create_header_bytes(0, 0x80, 0x84), None, False, NotImplementedError),
        (create_header_bytes(0, 0x30, 0x34), None, False, NotImplementedError),
        (create_header_bytes(0, 0x34, 0x38), None, False, NotImplementedError),
    ],
)
def test_identify_special_conditions(mocked_shimcache, file_data, ntversion, no_header, expected_value):
    mocked_shimcache.fh = file_data
    mocked_shimcache.ntversion = ntversion
    mocked_shimcache.noheader = no_header

    if ntversion:
        assert mocked_shimcache.identify() == expected_value
    else:
        with pytest.raises(expected_value):
            mocked_shimcache.identify()


@pytest.mark.parametrize(
    "version, expected_method",
    [
        (SHIMCACHE_WIN_TYPE.VERSION_WIN10_CREATORS, ShimCache.iter_win_8_plus),
        (SHIMCACHE_WIN_TYPE.VERSION_WIN10, ShimCache.iter_win_8_plus),
        (SHIMCACHE_WIN_TYPE.VERSION_WIN81, ShimCache.iter_win_8_plus),
        (SHIMCACHE_WIN_TYPE.VERSION_NT61, ShimCache.iter_nt),
        (SHIMCACHE_WIN_TYPE.VERSION_NT52, ShimCache.iter_nt),
    ],
)
def test_shim_cache_iterator_mocked(mocked_shimcache, version, expected_method):
    mocked_shimcache.version = version
    mocked_shimcache.ntversion = "6.3"

    with patch.object(ShimCache, expected_method.__name__) as iterator_method:
        assert iter(mocked_shimcache) == iterator_method.return_value


def test_shim_cache_iterator_unimplemented(mocked_shimcache):
    mocked_shimcache.version = -1
    with pytest.raises(NotImplementedError):
        iter(mocked_shimcache)


@pytest.mark.parametrize(
    "version, timestamp",
    [
        (SHIMCACHE_WIN_TYPE.VERSION_WIN10, wintimestamp(0)),
        (SHIMCACHE_WIN_TYPE.VERSION_WIN10_CREATORS, wintimestamp(0)),
        (SHIMCACHE_WIN_TYPE.VERSION_WIN81_NO_HEADER, None),
        (SHIMCACHE_WIN_TYPE.VERSION_WIN81, wintimestamp(0)),
    ],
)
def test_shim_iter_win8_plus(mocked_shimcache, created_header_win8plus, timestamp):
    win_10_variations, mocked_file = created_header_win8plus

    mocked_shimcache.fh = mocked_file.return_value

    output = list(mocked_shimcache.iter_win_8_plus(**win_10_variations))[0]
    if isinstance(output, tuple):
        assert output == (timestamp, "")
    else:
        assert isinstance(output, CRCMismatchException)


@pytest.mark.parametrize(
    "version, pathname, expected_output",
    [
        (
            SHIMCACHE_WIN_TYPE.VERSION_NT61,
            b"h\x00e\x00l\x00l\x00o\x00_\x00w\x00o\x00r\x00l\x00d\x00",
            [(wintimestamp(0), "hello_world")],
        ),
        (SHIMCACHE_WIN_TYPE.VERSION_NT61, b"hello_world", []),
    ],
)
def test_shim_iter_nt61(mocked_shimcache, mocked_nt61_file, expected_output):
    winnt_variations, open_file = mocked_nt61_file
    mocked_shimcache.fh = open_file

    assert list(mocked_shimcache.iter_nt(**winnt_variations)) == expected_output


@pytest.mark.parametrize(
    "pathname, expected_output",
    [
        (
            b"h\x00e\x00l\x00l\x00o\x00_\x00w\x00o\x00r\x00l\x00d\x00",
            [(wintimestamp(0), "hello_world")],
        ),
        (b"hello_world", []),
    ],
)
def test_shim_iter_nt52(mocked_shimcache, mocked_nt52_file, expected_output):
    winnt_variations, open_file = mocked_nt52_file
    mocked_shimcache.fh = open_file

    assert list(mocked_shimcache.iter_nt(**winnt_variations)) == expected_output


def list_generator(input_list: list):
    yield from input_list


def test_gracefull_shutdown_crc(mocked_shimcache, target_win):
    plugin = ShimcachePlugin(target_win)
    mocked_shimcache.version = SHIMCACHE_WIN_TYPE.VERSION_WIN10

    with patch(f"{ShimcachePlugin.__module__}.ShimcacheRecord") as mocked_record:
        list_gen = list_generator([CRCMismatchException(), (0, "path")])
        assert list(plugin._get_records(list_gen)) == [mocked_record.return_value]
