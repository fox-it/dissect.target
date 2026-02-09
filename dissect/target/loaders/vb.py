from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


class VBLoader(Loader):
    @staticmethod
    def detect(path: Path) -> bool:
        mft_exists = path.joinpath("MFT_C.bin").exists()
        c_drive_exists = path.joinpath("C_drive").exists()
        config_exists = path.joinpath("Windows/System32/config").exists()

        return (mft_exists or c_drive_exists) and config_exists

    def map(self, target: Target) -> None:
        remap_overlay = target.fs.append_layer()
        ntfs_overlay = target.fs.append_layer()
        dfs = DirectoryFilesystem(self.path, case_sensitive=False)
        target.filesystems.add(dfs)

        for f in dfs.listdir_ext("/"):
            if not f.name.endswith("_drive"):
                continue
            fh_mft = f.get("MFT_C.bin").open()
            fh_boot = f.get("$Boot").open()
            fh_sds = f.get("$Secure[ADS_$SDS]").open()

            try:
                fh_usnjrnl = f.get("$UsnJrnl_$J.bin").open()
            except FileNotFoundError:
                fh_usnjrnl = None

            fs = NtfsFilesystem(mft=fh_mft, boot=fh_boot, sds=fh_sds, usnjrnl=fh_usnjrnl)
            target.filesystems.add(fs)

            if f.name == "C_drive":
                ntfs_overlay.mount("sysvol", fs)
                remap_overlay.map_file("sysvol/$mft", fh_mft, "sysvol/$mft")
                if fh_usnjrnl:
                    remap_overlay.map_file("sysvol/$extend/$usnjrnl:$J", fh_usnjrnl, "sysvol/$extend/$usnjrnl:$J")
            drive = f.name.split("_")[0].lower()
            drive_letter = f"{drive}:"
            ntfs_overlay.mount(drive_letter, fs)
            remap_overlay.map_file(f"{drive_letter}/$mft", fh_mft, f"{drive_letter}/$mft")
            if fh_usnjrnl:
                remap_overlay.map_file(
                    f"{drive_letter}/$extend/$usnjrnl:$J",
                    fh_usnjrnl,
                    f"{drive_letter}/$extend/$usnjrnl:$J",
                )
