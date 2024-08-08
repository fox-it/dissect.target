import os
import stat
from datetime import datetime
from typing import Optional, TextIO

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystem import FilesystemEntry, LayerFilesystemEntry
from dissect.target.helpers import fsutil

# ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
STAT_TEMPLATE = """  File: {path} {symlink}
  Size: {size}          {filetype}
 Inode: {inode}   Links: {nlink}
Access: ({modeord}/{modestr})  Uid: ( {uid} )   Gid: ( {gid} )
Access: {atime}
Modify: {mtime}
Change: {ctime}"""

FALLBACK_LS_COLORS = "rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32"  # noqa: E501


def prepare_ls_colors() -> dict[str, str]:
    """Parse the LS_COLORS environment variable so we can use it later."""
    d = {}
    ls_colors = os.environ.get("LS_COLORS", FALLBACK_LS_COLORS)
    for line in ls_colors.split(":"):
        if not line:
            continue

        ft, _, value = line.partition("=")
        if ft.startswith("*"):
            ft = ft[1:]

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


def human_size(bytes: int, units: list[str] = ["", "K", "M", "G", "T", "P", "E"]) -> str:
    """Helper function to return the human readable string representation of bytes."""
    return str(bytes) + units[0] if bytes < 1024 else human_size(bytes >> 10, units[1:])


def stat_modestr(st: fsutil.stat_result) -> str:
    """Helper method for generating a mode string from a numerical mode value."""
    is_dir = "d" if stat.S_ISDIR(st.st_mode) else "-"
    dic = {"7": "rwx", "6": "rw-", "5": "r-x", "4": "r--", "0": "---"}
    perm = str(oct(st.st_mode)[-3:])
    return is_dir + "".join(dic.get(x, x) for x in perm)


def print_extensive_file_stat_listing(
    stdout: TextIO, name: str, entry: Optional[FilesystemEntry] = None, timestamp: Optional[datetime] = None
) -> None:
    """Print the file status as a single line"""
    if entry is not None:
        try:
            entry_stat = entry.lstat()
            if timestamp is None:
                timestamp = entry_stat.st_mtime
            symlink = f" -> {entry.readlink()}" if entry.is_symlink() else ""
            utc_time = datetime.utcfromtimestamp(timestamp).isoformat()

            print(
                (
                    f"{stat_modestr(entry_stat)} {entry_stat.st_uid:4d} {entry_stat.st_gid:4d} {entry_stat.st_size:6d} "
                    f"{utc_time} {name}{symlink}"
                ),
                file=stdout,
            )
            return
        except FileNotFoundError:
            pass
    print(f"??????????    ?    ?      ? ????-??-??T??:??:??.?????? {name}", file=stdout)


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
        if isinstance(entry, LayerFilesystemEntry):
            if entry.entries.fs.__type__ == "ntfs":
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
    subdirs = []

    if path.is_dir():
        contents = ls_scandir(path, color)
    elif path.is_file():
        contents = [(path, path.name)]

    if depth > 0:
        print(f"\n{str(path)}:", file=stdout)

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
            print_extensive_file_stat_listing(stdout, name, entry, show_time)
            if target_path.is_dir():
                subdirs.append(target_path)

    if recursive and subdirs:
        for subdir in subdirs:
            print_ls(subdir, depth + 1, stdout, long_listing, human_readable, recursive, use_ctime, use_atime, color)


def print_stat(path: fsutil.TargetPath, stdout: TextIO, dereference: bool = False):
    """Print file status"""
    symlink = f"-> {path.readlink()}" if path.is_symlink() else ""
    s = path.stat() if dereference else path.lstat()

    res = STAT_TEMPLATE.format(
        path=path,
        symlink=symlink,
        size=s.st_size,
        filetype="",
        inode=s.st_ino,
        nlink=s.st_nlink,
        modeord=oct(stat.S_IMODE(s.st_mode)),
        modestr=stat_modestr(s),
        uid=s.st_uid,
        gid=s.st_gid,
        atime=datetime.utcfromtimestamp(s.st_atime).isoformat(),
        mtime=datetime.utcfromtimestamp(s.st_mtime).isoformat(),
        ctime=datetime.utcfromtimestamp(s.st_ctime).isoformat(),
    )
    print(res, file=stdout)