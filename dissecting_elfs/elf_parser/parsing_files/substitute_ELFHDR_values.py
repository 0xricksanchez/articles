magic_dict = {"7f 45 4c 46": "7f 45 4c 46 (valid ELF magic)"}

arch_dict = {"0x1": "32-bit", "0x2": "64-bit"}

endian_dict = {"0x1": "little-endian", "0x2": "big-endian"}

version_dict = {"0x1": "1 (current version)"}

# often 0x0 by default (unset)
target_os_dict = {
    "0x0": "System V",
    "0x1": "HP-UX",
    "0x2": "NetBSD",
    "0x3": "Linux",
    "0x4": "GNU Hard",
    "0x6": "Solaris",
    "0x7": "AIX",
    "0x8": "IRIX",
    "0x9": "FreeBSD",
    "0xa": "Tru64",
    "0xb": "Novell Modesto",
    "0xc": "OpenBSD",
    "0xd": "OpenVMS",
    "0xe": "NonStop Kernel",
    "0xf": "AROS",
    "0x10": "Fenix OS",
    "0x11": "CloudABI",
}

file_type_dict = {
    "0x0": "ET_NONE (No file type)",
    "0x1": "ET_REL (Relocatable file)",
    "0x2": "ET_EXEC (Executable file)",
    "0x3": "ET_DYN (Shared object file)",
    "0x4": "ET_CORE (Core file)",
    "0xfe00": "ET_LOOS",
    "0xfeff": "ET_HIOS",
    "0xff00": "ET_LOPROC",
    "0xffff": "ET_HIPROC",
}

instr_set_dict = {
    "0x0": "no instr. set specified",
    "0x2": "SPARC",
    "0x3": "x86",
    "0x8": "MIPS",
    "0x14": "PowerPC",
    "0x16": "S390",
    "0x28": "ARM",
    "0x2a": "SuperH",
    "0x32": "IA-64",
    "0x3e": "x86-64",
    "0xb7": "AArch64",
    "0xf3": "RISC-V",
}
