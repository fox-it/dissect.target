from __future__ import annotations

from dissect.target.plugin import OperatingSystem

# Translate a Windows processor architecture value to a standardized machine name.
# https://learn.microsoft.com/en-us/windows/win32/winprog64/wow64-implementation-details
MACHINE_MAP_WINDOWS = {
    "AMD64": "x86_64",
    "EM64T": "x86_64",
    "IA64": "ia_64",
    "ARM64": "aarch64",
    "X86": "x86",  # unfortunately no way to be more specific (e.g. i686, i586, i386)
}

# Translate a ELF instruction set architecture (ISA) value to a standardized machine name.
# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#ISA
# https://en.wikipedia.org/wiki/Instruction_set_architecture
MACHINE_MAP_LINUX = {
    0x00: "unknown",
    0x02: "sparc",
    0x03: "x86",  # unfortunately no way to be more specific (e.g. i686, i586, i386)
    0x07: "i860",
    0x08: "mips",
    0x13: "i960",
    0x14: "powerpc32",
    0x15: "powerpc64",
    0x16: "s390",  # and s390x
    0x28: "aarch32",  # armv7
    0x2A: "superh",
    0x2B: "sparc64",
    0x32: "ia_64",
    0x3E: "x86_64",
    0xB7: "aarch64",  # armv8
    0xF3: "riscv64",
    0xF7: "bpf",
    0x102: "loongarch64",  # assuming 64
}


# Translate a Mach-O instruction CPU type to a standardized machine name.
# Cherry-picked to only architectures widely distributed by Apple.
# https://en.wikipedia.org/wiki/Mach-O, /usr/include/mach-o/loader.h & /usr/include/mach-o/machine.h
MACHINE_MAP_DARWIN = {
    0x00000006: "mc68k",  # CPU_TYPE_MC680x0
    0x06000000: "mc68k",
    0x00000007: "x86",  # CPU_TYPE_X86
    0x07000000: "x86",
    0x01000007: "x86_64",  # (CPU_TYPE_X86 | CPU_ARCH_ABI64)
    0x07000001: "x86_64",
    0x00000012: "powerpc32",  # CPU_TYPE_POWERPC
    0x12000000: "powerpc32",
    0x01000012: "powerpc64",  # CPU_TYPE_POWERPC64 = (CPU_TYPE_POWERPC | CPU_ARCH_ABI64)
    0x12000001: "powerpc64",
    0x0000000C: "aarch32",  # CPU_TYPE_ARM
    0x0C000000: "aarch32",
    0x0100000C: "aarch64",  # CPU_TYPE_ARM64 = (CPU_TYPE_ARM | CPU_ARCH_ABI64)
    0x0C000001: "aarch64",
    0x0200000C: "aarch64",  # CPU_TYPE_ARM64_32 = (CPU_TYPE_ARM | CPU_ARCH_ABI64_32)
    0x0C000002: "aarch64",
}


# Translate the operating system to it's corresponding vendor name.
# Linux derivatives generally translate to 'unknown', except Android, which translates to 'linux'.
OS_TO_VENDOR = {
    OperatingSystem.WINDOWS.value: "pc",
    OperatingSystem.MACOS.value: "apple",
    OperatingSystem.OSX.value: "apple",
    OperatingSystem.IOS.value: "apple",
    OperatingSystem.ANDROID.value: "linux",  # yes, really..
}


def target_triple(os: str, machine: str | int, bitness: int | None = None, endianness: int | None = None) -> str:
    """Generate a target triple with the given parameters in the format ``<machine>-<vendor>-<os>``.

    Does not omit part(s) of the triple to prevent ambiguous triples (I'm looking at you, GCC).

    Also does not include the fourth 'ABI' part (e.g. ``libc`` or ``gnu``).

    Resembles Rust's triples as close as possible since they have standardized their triples the best.

    The largest caveat is for x86 machines, which are always specified as 'x86' instead of e.g. 'i386', since
    we do not have machine CPU information available on-disk and ELF headers do not store which specific ISA
    they were compiled for. Feel free to improve this if you can think of a better method to further specify
    these machines.

    Currently ignores ``bitness`` and ``endianness`` parameters. Those could be used in future improved
    implementations of this function or to help with edge cases.

    References:
        - https://mcyoung.xyz/2025/04/14/target-triples/
        - https://doc.rust-lang.org/rustc/platform-support.html
        - https://llvm.org/doxygen/Triple_8cpp_source.html
        - https://llvm.org/doxygen/classllvm_1_1Triple.html
        - https://wiki.osdev.org/Target_Triplet
    """
    vendor = OS_TO_VENDOR.get(os, "unknown")

    if os == OperatingSystem.WINDOWS.value:
        if not isinstance(machine, str):
            raise ValueError(f"Unexpected machine type for windows: {machine!r}")
        machine = MACHINE_MAP_WINDOWS.get(machine, machine)

    elif os in (OperatingSystem.MACOS.value, OperatingSystem.OSX.value, OperatingSystem.IOS.value):
        if not isinstance(machine, int):
            raise ValueError(f"Unexpected machine type for darwin: {machine!r}")
        machine = MACHINE_MAP_DARWIN.get(machine, machine)

    elif isinstance(machine, int):
        machine = MACHINE_MAP_LINUX.get(machine, machine)

    else:
        raise ValueError(f"Unhandled machine value {machine!r} for OS {os}")

    return f"{machine}-{vendor}-{os}".lower()
