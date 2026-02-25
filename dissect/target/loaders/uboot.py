from __future__ import annotations

import bz2
import gzip
import lzma
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.cstruct import cstruct
from dissect.util.compression import lzop

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers import scrape
from dissect.target.loaders.scrape import BLOCK_SIZE, ScrapeLoader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target

uboot_def = """
/*
 * Operating System Codes
 */
enum IH_OS : uint8_t {
    INVALID             = 0             /* Invalid OS   */
    OPENBSD             = 1             /* OpenBSD      */
    NETBSD              = 2             /* NetBSD       */
    FREEBSD             = 3             /* FreeBSD      */
    4_4BSD              = 4             /* 4.4BSD       */
    LINUX               = 5             /* Linux        */
    SVR4                = 6             /* SVR4         */
    ESIX                = 7             /* Esix         */
    SOLARIS             = 8             /* Solaris      */
    IRIX                = 9             /* Irix         */
    SCO                 = 10            /* SCO          */
    DELL                = 11            /* Dell         */
    NCR                 = 12            /* NCR          */
    LYNXOS              = 13            /* LynxOS       */
    VXWORKS             = 14            /* VxWorks      */
    PSOS                = 15            /* pSOS         */
    QNX                 = 16            /* QNX          */
    U_BOOT              = 17            /* Firmware     */
    RTEMS               = 18            /* RTEMS        */
    ARTOS               = 19            /* ARTOS        */
    UNITY               = 20            /* Unity OS     */
    INTEGRITY           = 21            /* INTEGRITY    */
    OSE                 = 22            /* OSE          */
    PLAN9               = 23            /* Plan 9       */
};

/*
 * CPU Architecture Codes (supported by Linux)
 */
enum IH_ARCH : uint8_t {
    INVALID             = 0             /* Invalid CPU  */
    ALPHA               = 1             /* Alpha        */
    ARM                 = 2             /* ARM          */
    I386                = 3             /* Intel x86    */
    IA64                = 4             /* IA64         */
    MIPS                = 5             /* MIPS         */
    MIPS64              = 6             /* MIPS  64 Bit */
    PPC                 = 7             /* PowerPC      */
    S390                = 8             /* IBM S390     */
    SH                  = 9             /* SuperH       */
    SPARC               = 10            /* Sparc        */
    SPARC64             = 11            /* Sparc 64 Bit */
    M68K                = 12            /* M68K         */
    MICROBLAZE          = 14            /* MicroBlaze   */
    NIOS2               = 15            /* Nios-II      */
    BLACKFIN            = 16            /* Blackfin     */
    AVR32               = 17            /* AVR32        */
    ST200               = 18            /* STMicroelectronics ST200  */
    SANDBOX             = 19            /* Sandbox architecture (test only) */
    NDS32               = 20            /* ANDES Technology - NDS32  */
    OPENRISC            = 21            /* OpenRISC 1000  */
};

/*
 * Image Types
 *
 * "Standalone Programs" are directly runnable in the environment
 *      provided by U-Boot; it is expected that (if they behave
 *      well) you can continue to work in U-Boot after return from
 *      the Standalone Program.
 * "OS Kernel Images" are usually images of some Embedded OS which
 *      will take over control completely. Usually these programs
 *      will install their own set of exception handlers, device
 *      drivers, set up the MMU, etc. - this means, that you cannot
 *      expect to re-enter U-Boot except by resetting the CPU.
 * "RAMDisk Images" are more or less just data blocks, and their
 *      parameters (address, size) are passed to an OS kernel that is
 *      being started.
 * "Multi-File Images" contain several images, typically an OS
 *      (Linux) kernel image and one or more data images like
 *      RAMDisks. This construct is useful for instance when you want
 *      to boot over the network using BOOTP etc., where the boot
 *      server provides just a single image file, but you want to get
 *      for instance an OS kernel and a RAMDisk image.
 *
 *      "Multi-File Images" start with a list of image sizes, each
 *      image size (in bytes) specified by an "uint32_t" in network
 *      byte order. This list is terminated by an "(uint32_t)0".
 *      Immediately after the terminating 0 follow the images, one by
 *      one, all aligned on "uint32_t" boundaries (size rounded up to
 *      a multiple of 4 bytes - except for the last file).
 *
 * "Firmware Images" are binary images containing firmware (like
 *      U-Boot or FPGA images) which usually will be programmed to
 *      flash memory.
 *
 * "Script files" are command sequences that will be executed by
 *      U-Boot's command interpreter; this feature is especially
 *      useful when you configure U-Boot to use a real shell (hush)
 *      as command interpreter (=> Shell Scripts).
 */
enum IH_TYPE : uint8_t {
    INVALID             = 0             /* Invalid Image                */
    STANDALONE          = 1             /* Standalone Program           */
    KERNEL              = 2             /* OS Kernel Image              */
    RAMDISK             = 3             /* RAMDisk Image                */
    MULTI               = 4             /* Multi-File Image             */
    FIRMWARE            = 5             /* Firmware Image               */
    SCRIPT              = 6             /* Script file                  */
    FILESYSTEM          = 7             /* Filesystem Image (any type)  */
    FLATDT              = 8             /* Binary Flat Device Tree Blob */
    KWBIMAGE            = 9             /* Kirkwood Boot Image          */
    IMXIMAGE            = 10            /* Freescale IMXBoot Image      */
    UBLIMAGE            = 11            /* Davinci UBL Image            */
    OMAPIMAGE           = 12            /* TI OMAP Config Header Image  */
    AISIMAGE            = 13            /* TI Davinci AIS Image         */
    KERNEL_NOLOAD       = 14            /* OS Kernel Image, can run from any load address */
    PBLIMAGE            = 15            /* Freescale PBL Boot Image     */
};

/*
 * Compression Types
 */
enum IH_COMP : uint8_t {
    NONE                = 0             /*  No   Compression Used       */
    GZIP                = 1             /* gzip  Compression Used       */
    BZIP2               = 2             /* bzip2 Compression Used       */
    LZMA                = 3             /* lzma  Compression Used       */
    LZO                 = 4             /* lzo   Compression Used       */
};

#define IH_MAGIC        0x27051956      /* Image Magic Number           */
#define IH_NMLEN                32      /* Image Name Length            */

/*
 * Legacy format image header,
 * all data in network byte order (aka natural aka bigendian).
 */
typedef struct image_header {
    uint32_t    ih_magic;               /* Image Header Magic Number    */
    uint32_t    ih_hcrc;                /* Image Header CRC Checksum    */
    uint32_t    ih_time;                /* Image Creation Timestamp     */
    uint32_t    ih_size;                /* Image Data Size              */
    uint32_t    ih_load;                /* Data  Load  Address          */
    uint32_t    ih_ep;                  /* Entry Point Address          */
    uint32_t    ih_dcrc;                /* Image Data CRC Checksum      */
    IH_OS       ih_os;                  /* Operating System             */
    IH_ARCH     ih_arch;                /* CPU architecture             */
    IH_TYPE     ih_type;                /* Image Type                   */
    IH_COMP     ih_comp;                /* Compression Type             */
    char        ih_name[IH_NMLEN];      /* Image Name                   */
} image_header_t;
"""
c_uboot = cstruct(uboot_def, endian=">")

IH_MAGIC_BYTES = c_uboot.uint32(c_uboot.IH_MAGIC).dumps()


class UBootLoader(ScrapeLoader):
    """Generic loader for firmware images that may or may not contain U-Boot.

    Since there's not much to go on in terms of signatures or offsets, this loader will just do some generic checks
    and parsing of the file. Other than doing some specific U-Boot checks, this loader is very similar to the
    :class:`~dissect.target.loaders.scrape.ScrapeLoader`, which can be used as a fallback if this loader doesn't work.

    This loader is not guaranteed to work on all firmware images.
    If it doesn't and you think it should/could, please update it and submit a PR.
    """

    @staticmethod
    def detect(path: Path) -> bool:
        # Must be a file
        if not path.is_file():
            return False

        # Assume that firmware images are always nice round sizes, and not too large
        # (This is a very arbitrary list)
        if path.stat().st_size not in [mb * 1024 * 1024 for mb in (8, 16, 32, 64, 128, 256, 512)]:
            return False

        # Assume that a firmware image will contain U-Boot image magic bytes somewhere in the first 1 MiB of the file
        with path.open("rb") as fh:
            buf = fh.read(1 * 1024 * 1024)

        return any(needle in buf for needle in [IH_MAGIC_BYTES, b"U-Boot"])

    def map(self, target: Target) -> None:
        # First let the scrape loader find all filesystems
        super().map(target)

        vfs = VirtualFilesystem()

        # Do a second pass to find U-Boot images
        for _, offset, _ in scrape.find_needles(self.fh, IH_MAGIC_BYTES, start=0, block_size=BLOCK_SIZE):
            self.fh.seek(offset)

            header = c_uboot.image_header_t(self.fh)
            buf = self.fh.read(header.ih_size)

            try:
                if header.ih_comp == c_uboot.IH_COMP.GZIP:
                    buf = gzip.decompress(buf)
                elif header.ih_comp == c_uboot.IH_COMP.BZIP2:
                    buf = bz2.decompress(buf)
                elif header.ih_comp == c_uboot.IH_COMP.LZMA:
                    buf = lzma.decompress(buf)
                elif header.ih_comp == c_uboot.IH_COMP.LZO:
                    buf = lzop.decompress(buf)
            except Exception:
                target.log.warning("Failed to decompress U-Boot image at offset %#x", offset)

            name = header.ih_name.split(b"\x00")[0].decode()
            vfs.map_file_fh(f"{name} @ {offset:#x}", BytesIO(buf))

        target.fs.mount("$images$", vfs)
