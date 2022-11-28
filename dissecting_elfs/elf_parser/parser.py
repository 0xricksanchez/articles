#!/usr/bin/env python3

import argparse
import sys

from header_files.elfhdr import ELFHDR
from header_files.prgmhdr import PRGRM_HDR
from header_files.sctnhdr import SCTN_HDR


def get_byte_stream_at_offset(filestream, offset, size):
    filestream.seek(offset)
    byte_stream = filestream.read(size)
    return hex(int.from_bytes(byte_stream, byteorder="big"))


def get_endian_sensitive_value_at_offset(filestream, offset, size, endian):
    filestream.seek(offset)
    byte_stream = filestream.read(size)
    byte_stream.strip(b"\x00")
    if endian == "0x1":
        # little endian
        return hex(int.from_bytes(byte_stream, byteorder="little"))
    else:
        # big endian
        return hex(int.from_bytes(byte_stream, byteorder="big"))


def space_out_magic_bytes(magic_byte_string):
    return " ".join(magic_byte_string[i : i + 2] for i in range(0, len(magic_byte_string), 2)).lstrip("0x ")


def build_elfhdr(filepath):
    with open(filepath, "rb") as f:
        elfhdr = ELFHDR()
        # general ELF fields
        elfhdr.e_ident_EI_MAG = space_out_magic_bytes(get_byte_stream_at_offset(f, 0x0, 4))
        elfhdr.e_ident_EI_CLASS = get_byte_stream_at_offset(f, 0x4, 1)
        elfhdr.e_ident_EI_DATA = get_byte_stream_at_offset(f, 0x5, 1)
        elfhdr.e_ident_EI_VERSION = get_endian_sensitive_value_at_offset(f, 0x6, 1, elfhdr.e_ident_EI_DATA)
        elfhdr.e_ident_EI_OSABI = get_endian_sensitive_value_at_offset(f, 0x7, 1, elfhdr.e_ident_EI_DATA)
        elfhdr.e_ident_EI_PAD = get_endian_sensitive_value_at_offset(f, 0x8, 8, elfhdr.e_ident_EI_DATA)
        elfhdr.e_type = get_endian_sensitive_value_at_offset(f, 0x10, 2, elfhdr.e_ident_EI_DATA)
        elfhdr.e_machine = get_endian_sensitive_value_at_offset(f, 0x12, 2, elfhdr.e_ident_EI_DATA)
        elfhdr.e_version = get_endian_sensitive_value_at_offset(f, 0x14, 2, elfhdr.e_ident_EI_DATA)
        # now arch specific fields
        build_arch_specific_elfhdr(elfhdr, f)
        return elfhdr


def build_arch_specific_elfhdr(elfhdr, f):
    x86_ELFHDR_values = [
        (0x18, 4),
        (0x1C, 4),
        (0x20, 4),
        (0x24, 4),
        (0x28, 2),
        (0x2A, 2),
        (0x2C, 2),
        (0x2E, 2),
        (0x30, 2),
        (0x32, 2),
    ]
    x64_ELFHDR_values = [
        (0x18, 8),
        (0x20, 8),
        (0x28, 8),
        (0x30, 4),
        (0x34, 2),
        (0x36, 2),
        (0x38, 2),
        (0x3A, 2),
        (0x3C, 2),
        (0x3E, 2),
    ]
    if elfhdr.e_ident_EI_CLASS == "0x1":
        # x86
        arch_specfic_values = x86_ELFHDR_values
        elfhdr.e_entry = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[0][0],
            arch_specfic_values[0][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_phoff = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[1][0],
            arch_specfic_values[1][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_shoff = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[2][0],
            arch_specfic_values[2][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_flags = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[3][0],
            arch_specfic_values[3][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_ehsize = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[4][0],
            arch_specfic_values[4][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_phentsize = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[5][0],
            arch_specfic_values[5][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_phnum = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[6][0],
            arch_specfic_values[6][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_shentsize = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[7][0],
            arch_specfic_values[7][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_shnum = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[8][0],
            arch_specfic_values[8][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_shstridx = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[9][0],
            arch_specfic_values[9][1],
            elfhdr.e_ident_EI_DATA,
        )
    else:
        # x64
        arch_specfic_values = x64_ELFHDR_values
        elfhdr.e_entry = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[0][0],
            arch_specfic_values[0][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_phoff = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[1][0],
            arch_specfic_values[1][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_shoff = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[2][0],
            arch_specfic_values[2][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_flags = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[3][0],
            arch_specfic_values[3][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_ehsize = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[4][0],
            arch_specfic_values[4][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_phentsize = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[5][0],
            arch_specfic_values[5][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_phnum = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[6][0],
            arch_specfic_values[6][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_shentsize = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[7][0],
            arch_specfic_values[7][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_shnum = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[8][0],
            arch_specfic_values[8][1],
            elfhdr.e_ident_EI_DATA,
        )
        elfhdr.e_shstridx = get_endian_sensitive_value_at_offset(
            f,
            arch_specfic_values[9][0],
            arch_specfic_values[9][1],
            elfhdr.e_ident_EI_DATA,
        )


def build_prgrmhdr(filepath, elfhdr_obj):
    # program header fields
    results_arr = []
    with open(filepath, "rb") as f:
        prgrmhdr_offset = int(elfhdr_obj.e_phoff, 16)
        prgrmhdr_size = int(elfhdr_obj.e_phentsize, 16)
        prgrmhdr_num = int(elfhdr_obj.e_phnum, 16)
        for i in range(0, prgrmhdr_num):
            prgrmhdr = PRGRM_HDR()
            arch_specfic_values = prgrmhdr.modify_prghdr_offset_values(prgrmhdr_offset, elfhdr_obj.e_ident_EI_CLASS, i, prgrmhdr_size)
            if elfhdr_obj.e_ident_EI_CLASS == "0x1":
                prgrmhdr.p_type = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[0][0],
                    arch_specfic_values[0][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
                prgrmhdr.p_offset = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[1][0],
                    arch_specfic_values[1][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
                prgrmhdr.p_vaddr = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[2][0],
                    arch_specfic_values[2][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
                prgrmhdr.p_paddr = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[3][0],
                    arch_specfic_values[3][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
                prgrmhdr.p_filesz = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[4][0],
                    arch_specfic_values[4][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
                prgrmhdr.p_memsz = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[5][0],
                    arch_specfic_values[5][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
                prgrmhdr.p_flags = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[6][0],
                    arch_specfic_values[6][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
                prgrmhdr.p_align = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[7][0],
                    arch_specfic_values[7][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
            else:
                prgrmhdr.p_type = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[0][0],
                    arch_specfic_values[0][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
                prgrmhdr.p_flags = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[1][0],
                    arch_specfic_values[1][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
                prgrmhdr.p_offset = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[2][0],
                    arch_specfic_values[2][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
                prgrmhdr.p_vaddr = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[3][0],
                    arch_specfic_values[3][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
                prgrmhdr.p_paddr = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[4][0],
                    arch_specfic_values[4][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
                prgrmhdr.p_filesz = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[5][0],
                    arch_specfic_values[5][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
                prgrmhdr.p_memsz = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[6][0],
                    arch_specfic_values[6][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
                prgrmhdr.p_align = get_endian_sensitive_value_at_offset(
                    f,
                    arch_specfic_values[7][0],
                    arch_specfic_values[7][1],
                    elfhdr_obj.e_ident_EI_DATA,
                )
            results_arr.append(prgrmhdr)
    return results_arr


def build_sctnhdr(filepath, elfhdr_obj):
    # section header
    shstrtab = 0
    results_arr = []
    with open(filepath, "rb") as f:
        e_shoff = int(elfhdr_obj.e_shoff, 16)
        e_shentsize = int(elfhdr_obj.e_shentsize, 16)
        e_shnum = int(elfhdr_obj.e_shnum, 16)
        for i in range(0, e_shnum):
            sctnhdr = SCTN_HDR()
            arch_specfic_values = sctnhdr.modify_sctnhdr_offset_values(e_shoff, elfhdr_obj.e_ident_EI_CLASS, i, e_shentsize)
            sctnhdr.sh_name = get_endian_sensitive_value_at_offset(
                f,
                arch_specfic_values[0][0],
                arch_specfic_values[0][1],
                elfhdr_obj.e_ident_EI_DATA,
            )
            sctnhdr.sh_type = get_endian_sensitive_value_at_offset(
                f,
                arch_specfic_values[1][0],
                arch_specfic_values[1][1],
                elfhdr_obj.e_ident_EI_DATA,
            )
            sctnhdr.sh_flags = get_endian_sensitive_value_at_offset(
                f,
                arch_specfic_values[2][0],
                arch_specfic_values[2][1],
                elfhdr_obj.e_ident_EI_DATA,
            )
            sctnhdr.sh_addr = get_endian_sensitive_value_at_offset(
                f,
                arch_specfic_values[3][0],
                arch_specfic_values[3][1],
                elfhdr_obj.e_ident_EI_DATA,
            )
            sctnhdr.sh_offset = get_endian_sensitive_value_at_offset(
                f,
                arch_specfic_values[4][0],
                arch_specfic_values[4][1],
                elfhdr_obj.e_ident_EI_DATA,
            )
            sctnhdr.sh_size = get_endian_sensitive_value_at_offset(
                f,
                arch_specfic_values[5][0],
                arch_specfic_values[5][1],
                elfhdr_obj.e_ident_EI_DATA,
            )
            sctnhdr.sh_link = get_endian_sensitive_value_at_offset(
                f,
                arch_specfic_values[6][0],
                arch_specfic_values[6][1],
                elfhdr_obj.e_ident_EI_DATA,
            )
            sctnhdr.sh_info = get_endian_sensitive_value_at_offset(
                f,
                arch_specfic_values[7][0],
                arch_specfic_values[7][1],
                elfhdr_obj.e_ident_EI_DATA,
            )
            sctnhdr.sh_addralign = get_endian_sensitive_value_at_offset(
                f,
                arch_specfic_values[8][0],
                arch_specfic_values[8][1],
                elfhdr_obj.e_ident_EI_DATA,
            )
            sctnhdr.sh_entsize = get_endian_sensitive_value_at_offset(
                f,
                arch_specfic_values[9][0],
                arch_specfic_values[9][1],
                elfhdr_obj.e_ident_EI_DATA,
            )
            results_arr.append(sctnhdr)
            if sctnhdr.sh_type == "0x3":
                shstrtab = sctnhdr.sh_offset
        get_ascii_rep_of_sh_name(f, results_arr, shstrtab)
        return results_arr


def get_ascii_rep_of_sh_name(f, results_arr, shstrtab):
    for res in results_arr:
        sh_name_string_pos = int(res.sh_name, 16) + int(shstrtab, 16)
        f.seek(sh_name_string_pos)
        string_rep_of_sh_name = "".join(iter(lambda: f.read(1).decode("ascii"), "\x00"))
        res.sh_name = string_rep_of_sh_name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--all", help="get all information")
    parser.add_argument("-e", "--elfhdr", help="get information about the ELF header")
    parser.add_argument("-p", "--prghdr", help="get information about the program header")
    parser.add_argument("-s", "--sctnhdr", help="get information about all found section headers")
    args = parser.parse_args()

    elfhdr_obj = build_elfhdr(sys.argv[2])
    found_prgrmhdr = build_prgrmhdr(sys.argv[2], elfhdr_obj)
    found_sctnhdr = build_sctnhdr(sys.argv[2], elfhdr_obj)

    if not (args.all or args.elfhdr or args.prghdr or args.sctnhdr):
        print("Usage: python3 parser.py -a/e/p/s some_ELF_binary")
    elif args.all:
        elfhdr_obj.set_strings_in_elfhdr()
        elfhdr_obj.parse_output()
        for prghdr in found_prgrmhdr:
            prghdr.set_strings_in_prgmhdr()
            prghdr.parse_output()
        for sctn in found_sctnhdr:
            sctn.set_strings_in_sctnhdr()
            sctn.parse_output()
    elif args.elfhdr:
        elfhdr_obj.set_strings_in_elfhdr()
        elfhdr_obj.parse_output()
    elif args.prghdr:
        for prghdr in found_prgrmhdr:
            prghdr.set_strings_in_prgmhdr()
            prghdr.parse_output()
    elif args.sctnhdr:
        for sctn in found_sctnhdr:
            # sctn.set_strings_in_sctnhdr()
            sctn.parse_output()
    else:
        print("Usage: python3 parser.py -a/e/p/s some_ELF_binary")


if __name__ == "__main__":
    sys.exit(main())
