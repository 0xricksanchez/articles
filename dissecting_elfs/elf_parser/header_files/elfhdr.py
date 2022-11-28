from parsing_files.substitute_ELFHDR_values import arch_dict, endian_dict, file_type_dict, instr_set_dict, magic_dict, target_os_dict, version_dict
from tabulate import tabulate


class ELFHDR:
    def __init__(self):
        self.e_ident_EI_MAG = "unset"
        self.e_ident_EI_CLASS = "unset"
        self.e_ident_EI_DATA = "unset"
        self.e_ident_EI_VERSION = "unset"
        self.e_ident_EI_OSABI = "unset"
        self.e_ident_EI_PAD = "unset"
        self.e_type = "unset"
        self.e_machine = "unset"
        self.e_version = "unset"
        self.e_entry = "unset"
        self.e_phoff = "unset"
        self.e_shoff = "unset"
        self.e_flags = "unset"
        self.e_ehsize = "unset"
        self.e_phentsize = "unset"
        self.e_phnum = "unset"
        self.e_shentsize = "unset"
        self.e_shnum = "unset"
        self.e_shstridx = "unset"

    def set_magic(self):
        if self.e_ident_EI_MAG in magic_dict:
            self.e_ident_EI_MAG = magic_dict[self.e_ident_EI_MAG]
        else:
            self.e_ident_EI_MAG = self.e_ident_EI_MAG + " (invalid ELF magic)"

    def set_arch(self):
        if self.e_ident_EI_CLASS in arch_dict:
            self.e_ident_EI_CLASS = arch_dict[self.e_ident_EI_CLASS]

    def set_endian(self):
        if self.e_ident_EI_DATA in endian_dict:
            self.e_ident_EI_DATA = endian_dict[self.e_ident_EI_DATA]

    def set_os(self):
        if self.e_ident_EI_OSABI in target_os_dict:
            self.e_ident_EI_OSABI = target_os_dict[self.e_ident_EI_OSABI]

    def set_file_type(self):
        if self.e_type in file_type_dict:
            self.e_type = file_type_dict[self.e_type]

    def set_instr_set(self):
        if self.e_machine in instr_set_dict:
            self.e_machine = instr_set_dict[self.e_machine]

    def set_version(self):
        if self.e_ident_EI_VERSION in version_dict:
            self.e_ident_EI_VERSION = version_dict[self.e_ident_EI_VERSION]

    def set_entry_pnt(self, addr):
        self.entry_point = addr

    def set_prgmhdr(self):
        self.e_phoff = self.e_phoff + " ({} bytes into this file)".format(int(self.e_phoff, 16))
        self.e_phentsize = self.e_phentsize + " ({} bytes)".format(int(self.e_phentsize, 16))
        self.e_phnum = self.e_phnum + " ({})".format(int(self.e_phnum, 16))

    def set_sctnhdr(self):
        self.e_shoff = self.e_shoff + " ({} bytes into this file)".format(int(self.e_shoff, 16))
        self.e_shentsize = self.e_shentsize + " ({} bytes)".format(int(self.e_shentsize, 16))
        self.e_shnum = self.e_shnum + " ({})".format(int(self.e_shnum, 16))

    def set_size_elfhdr(self):
        self.e_ehsize = self.e_ehsize + " ({} bytes)".format(int(self.e_ehsize, 16))

    def set_string_index(self):
        self.e_shstridx = self.e_shstridx + " ({})".format(int(self.e_shstridx, 16))

    def set_strings_in_elfhdr(self):
        self.set_magic()
        self.set_arch()
        self.set_endian()
        self.set_version()
        self.set_os()
        self.set_file_type()
        self.set_instr_set()
        self.set_prgmhdr()
        self.set_sctnhdr()
        self.set_string_index()
        self.set_size_elfhdr()

    def parse_output(self):
        header = ["ELF HEADER"]
        data = [(k, v) for k, v in self.__dict__.items()]
        print(tabulate(data, header))
        print("--------------------  -------------------------------------")
