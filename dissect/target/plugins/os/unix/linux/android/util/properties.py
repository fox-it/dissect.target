from __future__ import annotations

from typing import TYPE_CHECKING, Any

from dissect.cstruct import cstruct

from dissect.target.helpers import configutil
from dissect.target.helpers.logging import get_logger
from dissect.target.helpers.protobuf import ProtobufVarint

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.filesystem import Filesystem

log = get_logger(__name__)


def find_build_props(fs: Filesystem) -> Iterator[Path]:
    """Search for Android ``build.prop`` files on the provided :class:`Filesystem`."""
    if (root_prop := fs.path("/build.prop")).is_file():
        yield root_prop

    for prop in fs.path("/").glob("*/build.prop"):
        if prop.is_file():
            yield prop


def parse_build_props(paths: Iterator[Path] | list[Path]) -> dict[str, Any]:
    """Parse Android ``build.prop`` files to a single dictionary."""
    props = {}
    for path in paths:
        try:
            props.update(
                configutil.parse(
                    path,
                    hint="meta_bare",
                    separator=("=",),
                    comment_prefixes=("#",),
                ).parsed_data
            )
        except Exception as e:  # noqa: PERF203
            log.warning("Unable to parse Android build.prop file %s: %s", path, e)
    return props


prop_def = """
struct property {
    uint8   r_type;
    varint  r_len;

    uint8   k_type;
    varint  k_len;
    char    key[k_len];

    uint8   v_type;
    varint  v_len;
    char    value[v_len];
};
"""
c_prop = cstruct(endian=">")
c_prop.add_custom_type("varint", ProtobufVarint, size=None, alignment=1, signed=False)
c_prop.load(prop_def, compiled=False)


def read_persistent_props(property_dir: Path) -> dict[str, str]:
    """Read ``/data/property`` persistent property files."""
    props = {}

    # Android version 9+ uses a protobuf file
    if (persistent_props := property_dir.joinpath("persistent_properties")).is_file():
        with persistent_props.open("rb") as fh:
            while True:
                try:
                    prop = c_prop.property(fh)
                except EOFError:
                    break
                props[prop.key.decode()] = prop.value.decode()

    # Android before version 9 uses separate files
    else:
        for file in property_dir.glob("persist.*"):
            props[file.name] = file.read_text().strip()

    return props
