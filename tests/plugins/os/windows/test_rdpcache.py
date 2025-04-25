from __future__ import annotations

import hashlib
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.windows.rdpcache import (
    BMP_DATA_OFFSET,
    BMP_MAGIC,
    BitmapTile,
    RdpCachePlugin,
    assemble_tiles_into_collage,
    c_bmp,
    extract_bin,
    extract_bmc,
    parse_color_data,
    tile_to_bitmap,
    wrap_square_colors_in_border,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target import Target
    from dissect.target.filesystem import VirtualFilesystem

BMC_PATH = absolute_path("_data/plugins/os/windows/rdpcache/bcache24.bmc")
BIN_PATH = absolute_path("_data/plugins/os/windows/rdpcache/Cache0000.bin")


@pytest.fixture
def target_win_rdp_cache(target_win_users: Target, fs_win: VirtualFilesystem) -> Target:
    fs_win.map_file("Users\\John\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\Cache0000.bin", BIN_PATH)
    fs_win.map_file("Users\\John\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\bcache24.bmc", BMC_PATH)

    target_win_users.add_plugin(RdpCachePlugin)

    return target_win_users


def test_wrap_in_border() -> None:
    """Test if ``rdpcache.wrap_square_colors_in_border`` behaves as expected."""

    grey_pixel = b"\x80\x80\x80\xff"
    blue_pixel = b"\xff\x00\x00\xff"
    grey_square = grey_pixel * 4  # A 2x2 square of grey pixels

    bordered_square = wrap_square_colors_in_border(grey_square, 2, blue_pixel, 2)

    # The square should now be 6x6 (2 lines added above, 2 on the left, 2 on the right, 2 on the bottom)
    assert len(bordered_square) == 6 * 6 * 4  # 4 bytes per pixel
    assert bordered_square.startswith(blue_pixel * 6)
    assert bordered_square.endswith(blue_pixel * 6)

    # Grab the third 'row' of the square (6 pixels horizontally, and 4 bytes per pixel)
    stripe = bordered_square[(6 * 3 * 4) : (6 * 4 * 4)]
    assert stripe == (blue_pixel * 2) + (grey_pixel * 2) + (blue_pixel * 2)


def test_bmc_no_remnants() -> None:
    """Test if ``rdpcache.extract_bmc`` behaves as expected."""

    with BMC_PATH.open("rb") as fh:
        tiles = list(extract_bmc(fh))

        # The test sample contains 'remnant tiles', but these contain no color data (its all null bytes)
        # We expect the parser to filter those out
        assert len(tiles) == 40
        assert not any(tile.is_remnant for tile in tiles)

        total_tile_data = b"".join(tile.colors for tile in tiles)
        assert hashlib.md5(total_tile_data).hexdigest() == "3fb7c485c7ee83e0d5d748d2e1c9d206"


def test_bin() -> None:
    """Test if ``rdpcache.extract_bin`` behaves as expected."""

    with BIN_PATH.open("rb") as fh:
        tiles = list(extract_bin(fh))

        assert len(tiles) == 254
        assert not any(tile.is_remnant for tile in tiles)
        total_tile_data = b"".join(tile.colors for tile in tiles)
        assert hashlib.md5(total_tile_data).hexdigest() == "7e7a88aa54efd92b3ab8e4f7b29afe3f"


def test_collage() -> None:
    """Test ``rdpcache.assemble_tiles_into_collage`` behaves as expected."""

    with BIN_PATH.open("rb") as fh:
        tiles = list(extract_bin(fh))
        collage_no_borders = assemble_tiles_into_collage(tiles)
        assert collage_no_borders.width == 64 * 64  # Rows should be max. 64 tiles
        assert collage_no_borders.height == 64 * 4  # 4
        assert hashlib.md5(collage_no_borders.colors).hexdigest() == "eabbe8a19e0d88ba15483eea0785dd39"

        collage_with_borders = assemble_tiles_into_collage(tiles, border_around_tile=2)
        assert hashlib.md5(collage_with_borders.colors).hexdigest() == "dbcd1181fd362570ae7b232aaeb136fa"
        assert collage_with_borders.width == 68 * 64  # Rows should be max. 64 tiles
        assert collage_with_borders.height == 68 * 4  # 47 rows


def test_bmp_export() -> None:
    """Test if we can convert a tile to a bitmap correctly."""

    grey_pixel = b"\x80\x80\x80\xff"
    square = grey_pixel * 16
    tile = BitmapTile(4, 4, square)

    bmp = tile_to_bitmap(tile)
    assert bmp == bytes.fromhex(
        "424dba000000000000007a0000006c00000004000000040000000100200003000000400000000000"
        "00000000000000000000000000000000ff0000ff0000ff000000000000ff206e6957000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000808080ff808080ff808080ff808080ff808080ff808080ff808080ff808080ff808080ff8080"
        "80ff808080ff808080ff808080ff808080ff808080ff808080ff"
    )

    bmp_fh = BytesIO(bmp)

    file_header = c_bmp.BITMAPFILEHEADER(bmp_fh)
    assert file_header.bfType == BMP_MAGIC
    assert file_header.bfOffBits == BMP_DATA_OFFSET
    bitmap_header = c_bmp.BITMAPV4HEADER(bmp_fh)
    assert bitmap_header.bV4Width == 4
    assert bitmap_header.bV4Height == 4
    assert bitmap_header.bV4SizeImage == 16 * 4  # 16 pixels of 4 bytes

    assert bmp_fh.read() == square  # The rest of the bitmap should be the color data


def test_parse_color_data() -> None:
    """Test ``rdpcache.parse_color_data`` behavior."""

    blue_color_half_transparency = b"\xff\x00\x00\x80"
    blue_square = blue_color_half_transparency * 4

    # The bmc parsing boosts transparency, replacing every fourth byte with 255
    assert parse_color_data(blue_square) == b"\xff\x00\x00\xff" * 4

    blue_pixel = b"\xff\x00\x00\xff"
    red_pixel = b"\x00\x00\xff\xff"

    blue_row = blue_pixel * 64
    red_row = red_pixel * 64

    # For BIN files, the tiles are saved 'top down' but we want to save them 'bottom up' later, as that is the BMP
    # default
    assert parse_color_data(blue_row + red_row, True, 64) == red_row + blue_row

    # While tiles are usually of width 64, they're not all like that. We want to be sure that color data isn't picked
    # up in chunks of 64 pixels only.
    blue_row = blue_pixel * 32
    red_row = red_pixel * 32
    assert parse_color_data(blue_row + red_row, True, 32) == red_row + blue_row


def test_rdp_cache_plugin(target_win_rdp_cache: Target, tmp_path: Path) -> None:
    """Test if the ``rdpcache.recover`` and ``rdpcache.paths`` behave as expected."""

    # Create a directory to extract the cache to
    cache_dst = tmp_path.joinpath("rdp_cache")
    cache_dst.mkdir()

    target_win_rdp_cache.rdpcache.recover(
        output_dir=cache_dst, no_individual_tiles=False, as_collage=True, as_grid=True, remnants=True
    )

    prefix = f"{target_win_rdp_cache.name}_John_"
    assert cache_dst.joinpath(f"{prefix}Cache0000.bin_grid.bmp").exists()
    assert cache_dst.joinpath(f"{prefix}Cache0000.bin_collage.bmp").exists()
    assert cache_dst.joinpath(f"{prefix}bcache24.bmc_grid.bmp").exists()
    assert cache_dst.joinpath(f"{prefix}bcache24.bmc_collage.bmp").exists()

    assert len(list(cache_dst.glob(f"{prefix}Cache0000.bin_*"))) == 256  # 254 tiles
    assert len(list(cache_dst.glob(f"{prefix}bcache24.bmc_*"))) == 42  # 39 tiles

    records = list(target_win_rdp_cache.rdpcache.paths())
    assert len(records) == 2
    assert records[0].path == "C:\\Users\\John\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\Cache0000.bin"
    assert records[1].path == "C:\\Users\\John\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\bcache24.bmc"
