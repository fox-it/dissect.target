from __future__ import annotations

import functools
import os
import stat
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal, NamedTuple, TextIO

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystem import LayerFilesystemEntry
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Sequence

    from dissect.target.helpers.fsutil import TargetPath


class LsEntry(NamedTuple):
    name: str
    path: TargetPath
    lstat: fsutil.stat_result | None = None


# ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
STAT_TEMPLATE = """  File: {path} {symlink}
  Size: {size}       Blocks: {blocks}    IO Block: {blksize}     {filetype}
Device: {device}     Inode: {inode}      Links: {nlink}
Access: ({modeord}/{modestr})  Uid: ( {uid} )   Gid: ( {gid} )
Access: {atime}
Modify: {mtime}
Change: {ctime}
 Birth: {btime}"""

# Output from `dircolors -b` on a Linux system
FALLBACK_LS_COLORS = "rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=00:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.7z=01;31:*.ace=01;31:*.alz=01;31:*.apk=01;31:*.arc=01;31:*.arj=01;31:*.bz=01;31:*.bz2=01;31:*.cab=01;31:*.cpio=01;31:*.crate=01;31:*.deb=01;31:*.drpm=01;31:*.dwm=01;31:*.dz=01;31:*.ear=01;31:*.egg=01;31:*.esd=01;31:*.gz=01;31:*.jar=01;31:*.lha=01;31:*.lrz=01;31:*.lz=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.lzo=01;31:*.pyz=01;31:*.rar=01;31:*.rpm=01;31:*.rz=01;31:*.sar=01;31:*.swm=01;31:*.t7z=01;31:*.tar=01;31:*.taz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tgz=01;31:*.tlz=01;31:*.txz=01;31:*.tz=01;31:*.tzo=01;31:*.tzst=01;31:*.udeb=01;31:*.war=01;31:*.whl=01;31:*.wim=01;31:*.xz=01;31:*.z=01;31:*.zip=01;31:*.zoo=01;31:*.zst=01;31:*.avif=01;35:*.jpg=01;35:*.jpeg=01;35:*.jxl=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:*~=00;90:*#=00;90:*.bak=00;90:*.crdownload=00;90:*.dpkg-dist=00;90:*.dpkg-new=00;90:*.dpkg-old=00;90:*.dpkg-tmp=00;90:*.old=00;90:*.orig=00;90:*.part=00;90:*.rej=00;90:*.rpmnew=00;90:*.rpmorig=00;90:*.rpmsave=00;90:*.swp=00;90:*.tmp=00;90:*.ucf-dist=00;90:*.ucf-new=00;90:*.ucf-old=00;90:"  # noqa: E501

# For easier and faster access to stat module functions and constants
S_ISREG = stat.S_ISREG
S_ISDIR = stat.S_ISDIR
S_ISLNK = stat.S_ISLNK
S_ISFIFO = stat.S_ISFIFO
S_ISSOCK = stat.S_ISSOCK
S_ISBLK = stat.S_ISBLK
S_ISCHR = stat.S_ISCHR
S_ISUID = stat.S_ISUID
S_ISGID = stat.S_ISGID
S_ISVTX = stat.S_ISVTX
S_IWOTH = stat.S_IWOTH
S_IXUGO = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH


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


@functools.cache
def file_type_from_mode(mode: int | None = None) -> str:
    """Helper method to get a LS_COLORS file type string from a file stat."""
    if mode is None:
        return "or"
    if S_ISREG(mode):
        file_type = "fi"
        if mode & S_ISUID:
            file_type = "su"
        elif mode & S_ISGID:
            file_type = "sg"
        elif mode & S_IXUGO:
            file_type = "ex"
    elif S_ISDIR(mode):
        file_type = "di"
        if (mode & S_ISVTX) and (mode & S_IWOTH):
            file_type = "tw"
        elif mode & S_IWOTH:
            file_type = "ow"
        elif mode & S_ISVTX:
            file_type = "st"
    elif S_ISLNK(mode):
        file_type = "ln"
    elif S_ISFIFO(mode):
        file_type = "pi"
    elif S_ISSOCK(mode):
        file_type = "so"
    elif S_ISBLK(mode):
        file_type = "bd"
    elif S_ISCHR(mode):
        file_type = "cd"
    else:
        file_type = "or"
    return file_type


def human_size(bytes: int, units: Sequence[str] = ("", "K", "M", "G", "T", "P", "E")) -> str:
    """Helper function to return the human readable string representation of bytes."""
    return str(bytes) + units[0] if bytes < 1024 else human_size(bytes >> 10, units[1:])


def stat_modestr(st: fsutil.stat_result) -> str:
    """Helper method for generating a mode string from a numerical mode value."""
    return stat.filemode(st.st_mode)


def print_ls_entry(
    *,
    stdout: TextIO,
    lsentry: LsEntry,
    time_attr: Literal["st_mtime", "st_atime", "st_ctime"] = "st_mtime",
    human_readable: bool = False,
    long_listing: bool = False,
    color: bool = False,
) -> None:
    """Print the LsEntry output as a single line."""
    if color:
        ft = file_type_from_mode(lsentry.lstat.st_mode) if lsentry.lstat else None
        name = fmt_ls_colors(ft, lsentry.name)
    else:
        name = lsentry.name

    if not long_listing:
        print(name, file=stdout)
        return

    if lsentry.lstat is None:
        hr_spaces = f"{'':5s}" if human_readable else " "
        regular_spaces = f"{'':10s}" if not human_readable else " "
        print(f"??????????    ?    ?{regular_spaces}?{hr_spaces}????-??-??T??:??:??.??????+??:?? {name}", file=stdout)
        return

    timestamp = getattr(lsentry.lstat, time_attr)
    symlink = f" -> {lsentry.path.readlink()}" if lsentry.path.is_symlink() else ""
    utc_time = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="microseconds")
    size = f"{human_size(lsentry.lstat.st_size):5s}" if human_readable else f"{lsentry.lstat.st_size:10d}"

    print(
        (
            f"{stat_modestr(lsentry.lstat)} {lsentry.lstat.st_uid:4d} {lsentry.lstat.st_gid:4d} {size} "
            f"{utc_time} {name}{symlink}"
        ),
        file=stdout,
    )


def get_ntfs_ads_ls_entries(path: TargetPath) -> list[LsEntry]:
    """Helper method to get NTFS alternative data stream entries for a given path."""
    entries = []
    # If we happen to scan an NTFS filesystem see if any of the
    # entries has an alternative data stream and also list them.
    entry = path.get()
    if isinstance(entry, LayerFilesystemEntry) and entry.entries.fs.__type__ == "ntfs":
        attrs = entry.lattr()
        for data_stream in attrs.DATA:
            if not data_stream.name:
                continue
            ads_name = f"{entry.name}:{data_stream.name}"
            ads_path = path.with_name(ads_name)
            try:
                lstat = ads_path.lstat()
            except FileNotFoundError:
                lstat = None
            entries.append(LsEntry(ads_name, ads_path, lstat))
    return entries


def print_ls(
    *,
    path: fsutil.TargetPath,
    depth: int,
    stdout: TextIO,
    long_listing: bool = False,
    human_readable: bool = False,
    recursive: bool = False,
    use_ctime: bool = False,
    use_atime: bool = False,
    sort_by_time: bool = False,
    reverse_sort: bool = False,
    color: bool = True,
) -> None:
    """Print ls output."""
    contents: list[LsEntry] = []
    for tpath in path.iterdir() if path.is_dir() else [path]:
        try:
            lstat = tpath.lstat()
        except FileNotFoundError:
            lstat = None
        contents.append(LsEntry(tpath.name, tpath, lstat))
        contents.extend(get_ntfs_ads_ls_entries(tpath))

    attr = "st_mtime"
    if sort_by_time:
        if use_ctime:
            attr = "st_ctime"
        elif use_atime:
            attr = "st_atime"
        contents.sort(key=lambda e: (getattr(e.lstat, attr), e.name) if e.lstat else (0, ""), reverse=True)
    else:
        contents.sort(key=lambda e: e.name)

    if reverse_sort:
        contents.reverse()

    if depth > 0:
        print(f"\n{path!s}:", file=stdout)

    if long_listing and len(contents) > 1:
        print(f"total {len(contents)}", file=stdout)

    subdirs: list[TargetPath] = []
    for lsentry in contents:
        print_ls_entry(
            stdout=stdout,
            lsentry=lsentry,
            time_attr=attr,
            human_readable=human_readable,
            long_listing=long_listing,
            color=color,
        )
        if recursive and not lsentry.path.is_symlink() and lsentry.path.is_dir():
            subdirs.append(lsentry.path)

    for subdir in subdirs:
        print_ls(
            path=subdir,
            depth=depth + 1,
            stdout=stdout,
            long_listing=long_listing,
            human_readable=human_readable,
            recursive=recursive,
            use_ctime=use_ctime,
            use_atime=use_atime,
            reverse_sort=reverse_sort,
            sort_by_time=sort_by_time,
            color=color,
        )


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
