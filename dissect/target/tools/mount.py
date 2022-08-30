import argparse
import logging

from dissect.target import Target, filesystem
from dissect.target.tools.utils import (
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


def main():
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.target",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )
    parser.add_argument("target", metavar="TARGET", help="target to load")
    parser.add_argument("mount", metavar="MOUNT", help="path to mount to")
    configure_generic_arguments(parser)
    args = parser.parse_args()

    if not HAS_FUSE:
        parser.exit("fusepy is not installed: pip install fusepy")

    process_generic_arguments(args)

    t = Target.open(args.target)
    vfs = filesystem.VirtualFilesystem()
    vfs.mount("fs", t.fs)

    for i, d in enumerate(t.disks):
        fname = f"disks/disk_{i}"
        vfs.map_file_fh(fname, d)

    for v in t.volumes:
        fname = f"volumes/{v.name}"
        vfs.map_file_fh(fname, v)

    log.info("Mounting to %s", args.mount)
    FUSE(DissectMount(vfs), args.mount, foreground=True, allow_other=True, nothreads=True, ro=True)


if __name__ == "__main__":
    main()
