import argparse
import logging
from typing import Union

from dissect.util.feature import Feature, feature_enabled

from dissect.target import Target, filesystem
from dissect.target.exceptions import TargetError
from dissect.target.helpers.utils import parse_options_string
from dissect.target.tools.utils import (
    catch_sigpipe,
    configure_generic_arguments,
    process_generic_arguments,
)

# Setting logging level to info for startup information.
logging.basicConfig(level=logging.INFO)

try:
    if feature_enabled(Feature.BETA):
        from fuse3 import FUSE3 as FUSE
        from fuse3 import util

        FUSE_VERSION = "3"
        FUSE_LIB_PATH = util.libfuse._name
    else:
        from fuse import FUSE, _libfuse

        FUSE_VERSION = "2"
        FUSE_LIB_PATH = _libfuse._name

    logging.info("Using fuse%s library: %s", FUSE_VERSION, FUSE_LIB_PATH)

    from dissect.target.helpers.mount import DissectMount

    HAS_FUSE = True
except Exception:
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

    args = parser.parse_args()

    process_generic_arguments(args)

    if not HAS_FUSE:
        parser.exit("fusepy is not installed: pip install fusepy")

    try:
        t = Target.open(args.target)
    except TargetError as e:
        log.error(e)
        log.debug("", exc_info=e)
        parser.exit(1)

    vfs = filesystem.VirtualFilesystem()
    vfs.mount("fs", t.fs)

    for i, d in enumerate(t.disks):
        fname = f"disks/disk_{i}"
        vfs.map_file_fh(fname, d)

    vnames = {}
    for i, v in enumerate(t.volumes):
        basename = f"{v.name or f'volume_{i}'}"
        fname = basename

        j = 1
        while fname in vnames:
            fname = f"{basename}_{j}"
            j += 1

        vnames[v] = fname
        vnames.setdefault(basename, []).append(v)
        vfs.map_file_fh(f"volumes/{fname}", v)

    for i, fs in enumerate(t.filesystems):
        fname = f"filesystems/{vnames[fs.volume] if fs.volume else f'fs_{i}'}"
        vfs.mount(fname, fs)

    # This is kinda silly because fusepy will convert this back into string arguments
    options = parse_options_string(args.options) if args.options else {}

    options["nothreads"] = True
    options["allow_other"] = True
    options["ro"] = True

    print(f"Mounting to {args.mount} with options: {_format_options(options)}")
    try:
        FUSE(DissectMount(vfs), args.mount, **options)
    except RuntimeError:
        parser.exit("FUSE error")


def _format_options(options: dict[str, Union[str, bool]]) -> str:
    return ",".join(key if value is True else f"{key}={value}" for key, value in options.items())


if __name__ == "__main__":
    main()
