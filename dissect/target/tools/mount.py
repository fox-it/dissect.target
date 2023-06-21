import argparse
import logging
from typing import Union

from dissect.target import Target, filesystem
from dissect.target.tools.utils import (
    catch_sigpipe,
    configure_generic_arguments,
    process_generic_arguments,
)

try:
    from fuse import FUSE

    from dissect.target.helpers.mount import DissectMount

    HAS_FUSE = True
except ImportError:
    HAS_FUSE = False

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


@catch_sigpipe
def main():
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.target",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )
    parser.add_argument("target", metavar="TARGET", help="target to load")
    parser.add_argument("mount", metavar="MOUNT", help="path to mount to")
    parser.add_argument("-o", "--options", help="additional FUSE options")
    configure_generic_arguments(parser)

    if not HAS_FUSE:
        parser.exit("fusepy is not installed: pip install fusepy")

    args = parser.parse_args()

    process_generic_arguments(args)

    t = Target.open(args.target)
    vfs = filesystem.VirtualFilesystem()
    vfs.mount("fs", t.fs)

    for i, d in enumerate(t.disks):
        fname = f"disks/disk_{i}"
        vfs.map_file_fh(fname, d)

    for i, v in enumerate(t.volumes):
        fname = f"volumes/{v.name or f'volume_{i}'}"
        vfs.map_file_fh(fname, v)

    for i, fs in enumerate(t.filesystems):
        fname = f"filesystems/{fs.volume.name if fs.volume else f'fs_{i}'}"
        vfs.mount(fname, fs)

    # This is kinda silly because fusepy will convert this back into string arguments
    options = _parse_options(args.options) if args.options else {}

    options["allow_other"] = True
    options["ro"] = True

    print(f"Mounting to {args.mount} with options: {_format_options(options)}")
    try:
        FUSE(DissectMount(vfs), args.mount, **options)
    except RuntimeError:
        parser.exit("FUSE error")


def _parse_options(options: str) -> dict[str, Union[str, bool]]:
    result = {}
    for opt in options.split(","):
        if "=" in opt:
            key, _, value = opt.partition("=")
            result[key] = value
        else:
            result[opt] = True
    return result


def _format_options(options: dict[str, Union[str, bool]]) -> str:
    return ",".join([key if value is True else f"{key}={value}" for key, value in options.items()])


if __name__ == "__main__":
    main()
