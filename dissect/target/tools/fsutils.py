from __future__ import annotations

import os
import stat
from datetime import datetime, timezone
from typing import TYPE_CHECKING, TextIO

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystem import FilesystemEntry, LayerFilesystemEntry
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Sequence

    from dissect.target.helpers.fsutil import TargetPath

# ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
STAT_TEMPLATE = """  File: {path} {symlink}
  Size: {size}       Blocks: {blocks}    IO Block: {blksize}     {filetype}
Device: {device}     Inode: {inode}      Links: {nlink}
Access: ({modeord}/{modestr})  Uid: ( {uid} )   Gid: ( {gid} )
Access: {atime}
Modify: {mtime}
Change: {ctime}
 Birth: {btime}"""

FALLBACK_LS_COLORS = "rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32"  # noqa: E501


def prepare_ls_colors() -> dict[str, str]:
    """Parse the LS_COLORS environment variable so we can use it later."""
    d = {}
    ls_colors = os.environ.get("LS_COLORS", FALLBACK_LS_COLORS)
    for line in ls_colors.split(":"):
        if not line:
            continue

        ft, _, value = line.partition("=")
        ft = ft.removeprefix("*")

        d[ft] = f"\x1b[{value}m{{}}\x1b[0m"

    return d


LS_COLORS = prepare_ls_colors()


def fmt_ls_colors(ft: str, name: str) -> str:
    """Helper method to colorize strings according to LS_COLORS."""
    try:
        return LS_COLORS[ft].format(name)
    except KeyError:
        pass

    try:
        return LS_COLORS[fsutil.splitext(name)[1]].format(name)
    except KeyError:
        pass

    return name


def human_size(bytes: int, units: Sequence[str] = ("", "K", "M", "G", "T", "P", "E")) -> str:
    """Helper function to return the human readable string representation of bytes."""
    return str(bytes) + units[0] if bytes < 1024 else human_size(bytes >> 10, units[1:])


def stat_modestr(st: fsutil.stat_result) -> str:
    """Helper method for generating a mode string from a numerical mode value."""
    return stat.filemode(st.st_mode)


def print_extensive_file_stat_listing(
    stdout: TextIO,
    name: str,
    entry: FilesystemEntry | None = None,
    timestamp: datetime | None = None,
    human_readable: bool = False,
) -> None:
    """Print the file status as a single line."""
    if entry is not None:
        try:
            entry_stat = entry.lstat()
        except FileNotFoundError:
            pass
        else:
            if timestamp is None:
                timestamp = entry_stat.st_mtime
            symlink = f" -> {entry.readlink()}" if entry.is_symlink() else ""
            utc_time = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="microseconds")
            size = f"{human_size(entry_stat.st_size):5s}" if human_readable else f"{entry_stat.st_size:10d}"

            print(
                (
                    f"{stat_modestr(entry_stat)} {entry_stat.st_uid:4d} {entry_stat.st_gid:4d} {size} "
                    f"{utc_time} {name}{symlink}"
                ),
                file=stdout,
            )
            return

    hr_spaces = f"{'':5s}" if human_readable else " "
    regular_spaces = f"{'':10s}" if not human_readable else " "

    print(f"??????????    ?    ?{regular_spaces}?{hr_spaces}????-??-??T??:??:??.??????+??:?? {name}", file=stdout)


def ls_scandir(path: fsutil.TargetPath, color: bool = False) -> list[tuple[fsutil.TargetPath, str]]:
    """List a directory for the given path."""
    result = []
    if not path.exists() or not path.is_dir():
        return []

    for file_ in path.iterdir():
        file_type = None
        if color:
            if file_.is_symlink():
                file_type = "ln"
            elif file_.is_dir():
                file_type = "di"
            elif file_.is_file():
                file_type = "fi"

        result.append((file_, fmt_ls_colors(file_type, file_.name) if color else file_.name))

        # If we happen to scan an NTFS filesystem see if any of the
        # entries has an alternative data stream and also list them.
        entry = file_.get()
        if isinstance(entry, LayerFilesystemEntry) and entry.entries.fs.__type__ == "ntfs":
            attrs = entry.lattr()
            for data_stream in attrs.DATA:
                if data_stream.name != "":
                    name = f"{file_.name}:{data_stream.name}"
                    result.append((file_, fmt_ls_colors(file_type, name) if color else name))

    result.sort(key=lambda e: e[0].name)

    return result


def print_ls(
    path: fsutil.TargetPath,
    depth: int,
    stdout: TextIO,
    long_listing: bool = False,
    human_readable: bool = False,
    recursive: bool = False,
    use_ctime: bool = False,
    use_atime: bool = False,
    color: bool = True,
) -> None:
    """Print ls output."""
    subdirs = []

    if path.is_dir():
        contents = ls_scandir(path, color)
    elif path.is_file():
        contents = [(path, path.name)]

    if depth > 0:
        print(f"\n{path!s}:", file=stdout)

    if not long_listing:
        for target_path, name in contents:
            print(name, file=stdout)
            if target_path.is_dir():
                subdirs.append(target_path)
    else:
        if len(contents) > 1:
            print(f"total {len(contents)}", file=stdout)
        for target_path, name in contents:
            try:
                entry = target_path.get()
                entry_stat = entry.lstat()
                show_time = entry_stat.st_mtime
                if use_ctime:
                    show_time = entry_stat.st_ctime
                elif use_atime:
                    show_time = entry_stat.st_atime
            except FileNotFoundError:
                entry = None
                show_time = None
            print_extensive_file_stat_listing(stdout, name, entry, show_time, human_readable)
            if target_path.is_dir():
                subdirs.append(target_path)

    if recursive and subdirs:
        for subdir in subdirs:
            print_ls(subdir, depth + 1, stdout, long_listing, human_readable, recursive, use_ctime, use_atime, color)


def print_stat(path: fsutil.TargetPath, stdout: TextIO, dereference: bool = False) -> None:
    """Print file status."""
    symlink = f"-> {path.readlink()}" if path.is_symlink() else ""
    s = path.stat() if dereference else path.lstat()

    def filetype(path: TargetPath) -> str:
        if path.is_dir():
            return "directory"
        if path.is_symlink():
            return "symbolic link"
        if path.is_file():
            return "regular file"
        return "unknown"

    res = STAT_TEMPLATE.format(
        path=path,
        symlink=symlink,
        size=s.st_size,
        filetype=filetype(path),
        device="?",
        inode=s.st_ino,
        blocks=s.st_blocks if s.st_blocks is not None else "?",
        blksize=s.st_blksize or "?",
        nlink=s.st_nlink,
        modeord=oct(stat.S_IMODE(s.st_mode)),
        modestr=stat_modestr(s),
        uid=s.st_uid,
        gid=s.st_gid,
        atime=datetime.fromtimestamp(s.st_atime, tz=timezone.utc).isoformat(timespec="microseconds"),
        mtime=datetime.fromtimestamp(s.st_mtime, tz=timezone.utc).isoformat(timespec="microseconds"),
        ctime=datetime.fromtimestamp(s.st_ctime, tz=timezone.utc).isoformat(timespec="microseconds"),
        btime=(
            datetime.fromtimestamp(s.st_birthtime, tz=timezone.utc).isoformat(timespec="microseconds")
            if hasattr(s, "st_birthtime") and s.st_birthtime
            else "?"
        ),
    )
    print(res, file=stdout)

    try:
        if (xattr := path.get().attr()) and isinstance(xattr, list) and hasattr(xattr[0], "name"):
            print("  Attr:")
            print_xattr(path.name, xattr, stdout)
    except Exception:
        pass


def print_xattr(basename: str, xattr: list, stdout: TextIO) -> None:
    """Mimics getfattr -d {file} behaviour."""
    if not hasattr(xattr[0], "name"):
        return

    XATTR_TEMPLATE = "# file: {basename}\n{attrs}"
    res = XATTR_TEMPLATE.format(
        basename=basename, attrs="\n".join([f'{attr.name}="{attr.value.decode()}"' for attr in xattr])
    )
    print(res, file=stdout)
