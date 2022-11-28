from parsing_files.substitute_PRGRMHDR_values import flag_dict, type_dict
from tabulate import tabulate


class PRGRM_HDR:
    def __init__(self):
        self.p_type = "unset"
        self.p_offset = "unset"
        self.p_vaddr = "unset"
        self.p_paddr = "unset"
        self.p_filesz = "unset"
        self.p_memsz = "unset"
        self.p_flags = "unset"
        self.p_align = "unset"

    @staticmethod
    def modify_prghdr_offset_values(proghdr_offset, arch, entry_number, prghdr_size):
        x86_PRGRMHDR_values = [
            [0x00, 4],
            [0x04, 4],
            [0x08, 4],
            [0x0C, 4],
            [0x10, 4],
            [0x14, 4],
            [0x18, 4],
            [0x1C, 4],
        ]
        x64_PRGRMHDR_values = [
            [0x00, 4],
            [0x04, 4],
            [0x08, 8],
            [0x10, 8],
            [0x18, 8],
            [0x20, 8],
            [0x28, 8],
            [0x30, 8],
        ]
        if arch == "0x1":
            arch_specfic_arr = x86_PRGRMHDR_values
        else:
            arch_specfic_arr = x64_PRGRMHDR_values
        for arr in arch_specfic_arr:
            arr[0] += proghdr_offset + prghdr_size * entry_number
        return arch_specfic_arr

    def set_type(self):
        if self.p_type in type_dict:
            self.p_type = type_dict[self.p_type]

    def set_permissions(self):
        if self.p_flags in flag_dict:
            self.p_flags = flag_dict[self.p_flags]

    def set_offset(self):
        if self.p_offset != "unset":
            self.p_offset = self.p_offset + " ({} bytes into this file)".format(int(self.p_offset, 16))

    def set_psize(self):
        if self.p_filesz != "unset":
            self.p_filesz = self.p_filesz + " ({} bytes)".format(int(self.p_filesz, 16))

    def set_msize(self):
        if self.p_memsz != "unset":
            self.p_memsz = self.p_memsz + " ({} bytes)".format(int(self.p_memsz, 16))

    def set_strings_in_prgmhdr(self):
        self.set_type()
        self.set_permissions()
        self.set_offset()
        self.set_psize()
        self.set_msize()

    def parse_output(self):
        header = ["FOUND PROGRAM HEADER"]
        data = [(k, v) for k, v in self.__dict__.items()]
        print(tabulate(data, header))
        print("--------------------------  ----------------------")
