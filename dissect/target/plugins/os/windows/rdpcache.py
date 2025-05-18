from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.cstruct import cstruct

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, arg, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target

bitmap_cache_def = """
// https://www.cert.ssi.gouv.fr/actualite/CERTFR-2016-ACT-017/
struct bin_header {
    CHAR    magic[8];
    DWORD   version;
};

struct bin_tile_header {
    DWORD   key1;
    DWORD   key2;
    WORD    tile_width;
    WORD    tile_height;
};

struct bmc_tile_header {
    DWORD   key1;
    DWORD   key2;
    WORD    tile_width;
    WORD    tile_height;
    DWORD   tile_length;
    DWORD   tile_params_unk_1: 3;
    DWORD   tile_params_compression: 1;
    DWORD   tile_params_unk_2: 28;
};
"""

bitmap_def = """
// https://stackoverflow.com/questions/20864752/how-is-defined-the-data-type-fxpt2dot30-in-the-bmp-file-structure
typedef LONG FXPT2DOT30;

// https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-ciexyz
struct CIEXYZ {
    FXPT2DOT30  ciexyzX;
    FXPT2DOT30  ciexyzY;
    FXPT2DOT30  ciexyzZ;
};

// https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-ciexyztriple
struct CIEXYZTRIPLE {
    CIEXYZ  ciexyzRed;
    CIEXYZ  ciexyzGreen;
    CIEXYZ  ciexyzBlue;
};

// https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapfileheader
struct BITMAPFILEHEADER {
    WORD    bfType;
    DWORD   bfSize;
    WORD    bfReserved1;
    WORD    bfReserved2;
    DWORD   bfOffBits;
};

// https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapv4header
struct BITMAPV4HEADER {
    DWORD           bV4Size;
    LONG            bV4Width;
    LONG            bV4Height;
    WORD            bV4Planes;
    WORD            bV4BitCount;
    DWORD           bV4V4Compression;
    DWORD           bV4SizeImage;
    LONG            bV4XPelsPerMeter;
    LONG            bV4YPelsPerMeter;
    DWORD           bV4ClrUsed;
    DWORD           bV4ClrImportant;
    DWORD           bV4RedMask;
    DWORD           bV4GreenMask;
    DWORD           bV4BlueMask;
    DWORD           bV4AlphaMask;
    DWORD           bV4CSType;
    CIEXYZTRIPLE    bV4Endpoints;
    DWORD           bV4GammaRed;
    DWORD           bV4GammaGreen;
    DWORD           bV4GammaBlue;
};
"""

c_bitmap_cache = cstruct().load(bitmap_cache_def)
c_bmp = cstruct().load(bitmap_def)

BMP_MAGIC = int.from_bytes(b"BM", "little")
BIN_MAGIC = b"RDP8bmp\x00"

BMP_DATA_OFFSET = len(c_bmp.BITMAPFILEHEADER) + len(c_bmp.BITMAPV4HEADER)  # 122

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmf/eb4bbd50-b3ce-4917-895c-be31f214797f
LCS_WINDOWS_COLOR_SPACE = int.from_bytes(b"Win ", "big")

# This member is ignored unless the bV4CSType member specifies LCS_CALIBRATED_RGB. We therefore prepare an empty logical
# color space for when we export our BMPs
EMPTY_LOGICAL_COLOR_SPACE = c_bmp.CIEXYZTRIPLE(
    ciexyzRed=c_bmp.CIEXYZ(ciexyzX=0, ciexyzY=0, ciexyzZ=0),
    ciexyzGreen=c_bmp.CIEXYZ(ciexyzX=0, ciexyzY=0, ciexyzZ=0),
    ciexyzBlue=c_bmp.CIEXYZ(ciexyzX=0, ciexyzY=0, ciexyzZ=0),
)
EMPTY_PIXEL = b"\xff\xff\xff\x00"  # Transparent white pixel
BORDER_PIXEL = b"\x80\x80\x80\xff"  # Grey pixel


RDPCacheRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/rdp/cache",
    [
        ("datetime", "ctime"),
        ("datetime", "mtime"),
        ("path", "path"),
    ],
)


@dataclass
class BitmapTile:
    width: int
    height: int
    colors: bytes
    is_remnant: bool = False


def parse_color_data(data: bytes, reverse_rows: bool = False, row_width: int = 64) -> bytes:
    """Parse bitmap color data.

    Optionally can reverse the row order of the bitmap data, which is useful when parsing a
    bitmap that is top-down when you want it to be bottom-up (like in .bin files). Assumes 32 bits-per-pixel.
    """
    color_data = b""
    row = b""
    while len(data) > 0:
        chunk = data[:3] + b"\xff"
        data = data[4:]
        if reverse_rows:
            row += chunk
            if len(row) % (row_width * 4) == 0:
                # We have read a row
                # Prepend the row to the output data, essentially reversing the row order
                color_data = row + color_data
                row = b""
        else:
            color_data += chunk
    return color_data


def tile_to_bitmap(tile: BitmapTile) -> bytes:
    """Given a tile, convert it to a valid bitmap file."""
    file_header_new = c_bmp.BITMAPFILEHEADER(
        bfType=BMP_MAGIC,
        bfSize=len(tile.colors) + BMP_DATA_OFFSET,
        bfReserved1=0,
        bfReserved2=0,
        bfOffBits=BMP_DATA_OFFSET,
    )

    info_header_new = c_bmp.BITMAPV4HEADER(
        bV4Size=len(c_bmp.BITMAPV4HEADER),
        bV4Width=tile.width,
        bV4Height=tile.height,
        bV4Planes=1,
        bV4BitCount=32,
        bV4V4Compression=3,
        bV4SizeImage=len(tile.colors),
        bV4XPelsPerMeter=0,
        bV4YPelsPerMeter=0,
        bV4ClrUsed=0,
        bV4ClrImportant=0,
        bV4RedMask=0xFF0000,
        bV4GreenMask=0xFF00,
        bV4BlueMask=0xFF,
        bV4AlphaMask=0xFF000000,
        bV4CSType=LCS_WINDOWS_COLOR_SPACE,
        bV4Endpoints=EMPTY_LOGICAL_COLOR_SPACE,
        bV4GammaRed=0,
        bV4GammaGreen=0,
        bV4GammaBlue=0,
    )
    return file_header_new.dumps() + info_header_new.dumps() + tile.colors


def wrap_square_colors_in_border(colors: bytes, side_length: int, border_pixel: bytes, border_thickness: int) -> bytes:
    """Wrap color data in a colored-border."""
    while border_thickness > 0:
        border_thickness -= 1

        # Add a bottom row, Add a top row, Add a left-row and a right-row
        border_row = border_pixel * (side_length + 2)
        new_colors = b""
        for i in range(side_length):
            offset = i * side_length * 4  # 4 bytes per pixel

            color_slice = colors[offset : offset + side_length * 4]

            # Add a border-pixel to the left and right of this 'stripe'
            new_colors += border_pixel + color_slice + border_pixel

        # Add a border-stripe on top and on the bottom
        colors = border_row + new_colors + border_row

        # We have increased the size of the tile with 2 (one pixel on each end)
        side_length += 2

    return colors


def assemble_tiles_into_collage(tiles: list[BitmapTile], border_around_tile: int = 0) -> BitmapTile:
    """Assemble a list of tiles into one tile containing all color data."""
    tiles_in_row = 64
    rows: list[list[bytes]] = [[]]
    current_row = 0

    if not isinstance(border_around_tile, int) or border_around_tile < 0:
        raise ValueError("Argument border_around_tile should be zero or a positive integer.")

    tile_length = 64 + (border_around_tile * 2)

    padding_tile = EMPTY_PIXEL * tile_length * tile_length

    for tile in tiles:
        padding_color_data = ((64 * 64) - (tile.width * tile.height)) * EMPTY_PIXEL
        tile_color_data = tile.colors + padding_color_data

        if len(rows[current_row]) == tiles_in_row:
            current_row += 1
            rows.append([])

        if border_around_tile > 0:
            tile_color_data = wrap_square_colors_in_border(tile_color_data, 64, BORDER_PIXEL, border_around_tile)
        rows[current_row].append(tile_color_data)

    # If we only have one row (because there are not enough tiles) we decrease the collage width
    tiles_in_row = min(tiles_in_row, len(tiles))

    # Add padding tiles to the last row
    while len(rows[current_row]) < tiles_in_row:
        rows[current_row].append(padding_tile)

    final_image: list[bytes] = []
    for row in rows:
        # We can't dump every tile's color data one after another, as bitmaps go row-by-row. We 'slice' each horizontal
        # line from each tile, concat them to one another into one line of the final collage, and add that line to the
        # final image
        for i in range(tile_length):
            for tile_color_data in row:
                tile_data_size = tile_length * 4  # 4 bytes per pixel
                offset = i * tile_data_size
                line_from_tile = tile_color_data[offset : offset + tile_data_size]
                final_image.append(line_from_tile)

    collage_width = tiles_in_row * tile_length
    collage_height = tile_length * len(rows)
    return BitmapTile(collage_width, collage_height, b"".join(final_image))


def extract_bin(fh: BinaryIO) -> Iterator[BitmapTile]:
    """Extract bitmap tiles from a Cache000[1-4].bin bitmap cache file.

    These files are found on modern Windows versions.
    """
    fh.seek(0)
    bin_header = c_bitmap_cache.bin_header(fh)
    if bin_header.magic != BIN_MAGIC:
        raise ValueError(f"Invalid BIN file magic: {bin_header.magic}")

    while True:
        try:
            tile_header = c_bitmap_cache.bin_tile_header(fh)
        except EOFError:
            break
        tile_length = 4 * tile_header.tile_width * tile_header.tile_height
        colors = parse_color_data(fh.read(tile_length), reverse_rows=True, row_width=tile_header.tile_width)
        yield BitmapTile(tile_header.tile_width, tile_header.tile_height, colors)


def extract_bmc(fh: BinaryIO) -> Iterator[BitmapTile]:
    """Extract bitmap cache from bmc files, which are typically found on older Windows versions."""
    fh.seek(0)
    while True:
        try:
            tile_header = c_bitmap_cache.bmc_tile_header(fh)
        except EOFError:
            break

        if tile_header.tile_params_compression:
            raise NotImplementedError("No support for compressed bmc files")

        bytes_per_pixel = tile_header.tile_length // (tile_header.tile_width * tile_header.tile_height)
        if bytes_per_pixel != 4:
            if not (0 <= bytes_per_pixel <= 4):
                raise ValueError(f"Unexpected bpp value {bytes_per_pixel}")
            else:
                raise NotImplementedError("No support for bmc files with a bits-per-pixel other than 32")

        tile_size = bytes_per_pixel * tile_header.tile_width * tile_header.tile_height
        tile_colors = parse_color_data(fh.read(tile_size))
        yield BitmapTile(tile_header.tile_width, tile_header.tile_height, tile_colors)

        # Unlike bin-files, bmc files are pre-allocated with space for 64x64 pixel tiles. Whenever a tile is not exactly
        # 64 by 64, the remaining bytes until the next allocated slot are likely to contain leftover data from (a)
        # previous tile(s). bmc-tools calls these artefacts 'old' tiles, we call them 'remnant' tiles

        old_color_data_length = (64 * 64 - (tile_header.tile_width * tile_header.tile_height)) * bytes_per_pixel
        if old_color_data_length != 0:
            remnant_tile_colors = fh.read(old_color_data_length)
            if remnant_tile_colors == b"\x00" * old_color_data_length:
                # It's only null bytes, there is no content here
                continue
            if remnant_tile_colors == b"":
                # We have reached the end of the file, there's no color data after this tile
                break
            yield BitmapTile(
                64 - tile_header.tile_width,
                64 - tile_header.tile_height,
                remnant_tile_colors,
                is_remnant=True,
            )


class RdpCachePlugin(Plugin):
    """Plugin to extract the RDP Bitmap Cache from a Windows target.

    Resources:
        - https://www.cert.ssi.gouv.fr/actualite/CERTFR-2016-ACT-017/
    """

    __namespace__ = "rdpcache"

    CACHE_PATH = "AppData/Local/Microsoft/Terminal Server Client/Cache/"
    GLOBS = ("Cache*.bin", "bcache2*.bmc")

    def __init__(self, target: Target):
        super().__init__(target)
        self._caches: list[tuple[UserDetails, TargetPath]] = []

        for user_details in self.target.user_details.all_with_home():
            user_rdp_cache = user_details.home_path.joinpath(self.CACHE_PATH)
            for glob in self.GLOBS:
                for cache_path in user_rdp_cache.glob(glob):
                    if cache_path.lstat().st_size > 0:
                        self._caches.append((user_details, cache_path))

    def check_compatible(self) -> None:
        """At least one bitmap cache file with contents is necessary."""
        if not self._caches:
            raise UnsupportedPluginError("No RDP Cache files found on target")

    def _recover_tiles_from_cache(self, path: TargetPath) -> Iterator[BitmapTile]:
        """Given a target path, select the correct extraction method and yield bitmap tiles."""
        fh = path.open("rb")
        if fh.read(len(BIN_MAGIC)) == BIN_MAGIC:
            yield from extract_bin(fh)
        else:
            yield from extract_bmc(fh)

    @export(record=RDPCacheRecord)
    def paths(self) -> Iterator[RDPCacheRecord]:
        """Yield paths and timestamps of RDP Cache bitmap files."""
        for user_details, path in self._caches:
            lstat = path.lstat()
            yield RDPCacheRecord(
                ctime=lstat.st_ctime,
                mtime=lstat.st_mtime,
                path=path,
                _user=user_details.user,
                _target=self.target,
            )

    @arg("-o", "--output", dest="output_dir", type=Path, required=True, help="path to recover bitmap files to")
    @arg(
        "-g",
        "--grid",
        dest="as_grid",
        action="store_true",
        help="assemble all recovered tiles of a cache into a single grid image with borders around each tile",
    )
    @arg(
        "-c",
        "--collage",
        dest="as_collage",
        action="store_true",
        help="assemble all recovered tiles of a cache into one image",
    )
    @arg(
        "-n",
        "--no-tiles",
        dest="no_individual_tiles",
        action="store_true",
        help="do not save each recovered tile as a separate bitmap",
    )
    @arg(
        "-r",
        "--remnants",
        choices=["only", "include", "exclude"],
        default="exclude",
        help="include old leftover colordata in between tiles as separate, 'remnant' tiles",
    )
    @export(output="none")
    def recover(
        self, output_dir: Path, no_individual_tiles: bool, as_collage: bool, as_grid: bool, remnants: str
    ) -> None:
        """Extract bitmaps from Windows' RDP Client cache files."""

        if not output_dir.exists():
            self.target.log.error("Destination folder does not exist: %s", output_dir)
            return

        if not as_grid and not as_collage and no_individual_tiles:
            self.target.log.error("No export setting specified (one of --grid, --collage, --no-tiles)")
            return

        include_remnants = remnants == "only" or remnants == "include"
        exclude_regular_tiles = remnants == "only"

        for user_details, path in self._caches:
            prefix = f"{self.target.name}_{user_details.user.name}_{path.name}_"
            regular_tiles = []
            remnant_tiles = []
            for i, tile in enumerate(self._recover_tiles_from_cache(path)):
                if tile.is_remnant:
                    remnant_tiles.append(tile)
                    if not include_remnants:
                        continue
                    filename = f"{prefix}remnant_{i}.bmp"
                else:
                    regular_tiles.append(tile)
                    if exclude_regular_tiles:
                        continue
                    filename = f"{prefix}{i}.bmp"

                if not no_individual_tiles:
                    output_dir.joinpath(filename).write_bytes(tile_to_bitmap(tile))

            if include_remnants and not remnant_tiles:
                self.target.log.info("No remnant tile data found for %s", path)

            elif remnant_tiles and not include_remnants:
                self.target.log.warning("Remnant tile data found for %s, but remnant setting is set to exclude", path)

            if path.name.endswith(".bin"):
                # For bin files, collages look better if we assemble them in reverse order
                regular_tiles.reverse()
                remnant_tiles.reverse()

            assemble_settings = []
            if as_collage:
                assemble_settings.append(("collage", 0))
            if as_grid:
                assemble_settings.append(("grid", 2))

            valid_tile_sets = []
            if regular_tiles and not exclude_regular_tiles:
                valid_tile_sets.append(("", regular_tiles))

            if remnant_tiles and include_remnants:
                valid_tile_sets.append(("remnants_", remnant_tiles))

            for assemble_name, border_around_tile in assemble_settings:
                for tile_type_name, tiles in valid_tile_sets:
                    file = output_dir.joinpath(f"{prefix}{tile_type_name}{assemble_name}.bmp")
                    try:
                        file.write_bytes(tile_to_bitmap(assemble_tiles_into_collage(tiles, border_around_tile)))
                    except Exception as e:
                        self.target.log.error("Unable to write bitmap to file %s: %s", file, e)  # noqa: TRY400
                        self.target.log.debug("", exc_info=e)
