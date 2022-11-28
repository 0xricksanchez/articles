from parsing_files.substitute_SCTNHDR_values import flag_dict, type_dict
from tabulate import tabulate


class SCTN_HDR:
    def __init__(self):
        self.sh_name = "unset"
        self.sh_type = "unset"
        self.sh_flags = "unset"
        self.sh_addr = "unset"
        self.sh_offset = "unset"
        self.sh_size = "unset"
        self.sh_link = "unset"
        self.sh_info = "unset"
        self.sh_addralign = "unset"
        self.sh_entsize = "unset"

    @staticmethod
    def modify_sctnhdr_offset_values(sectnhdr_offset, arch, entry_number, sectnhdr_size):
        x86_SCTNHDR_values = [
            [0x00, 4],
            [0x04, 4],
            [0x08, 4],
            [0x0C, 4],
            [0x10, 4],
            [0x14, 4],
            [0x18, 4],
            [0x1C, 4],
            [0x20, 4],
            [0x24, 4],
        ]
        x64_SCTNHDR_values = [
            [0x00, 4],
            [0x04, 4],
            [0x08, 8],
            [0x10, 8],
            [0x18, 8],
            [0x20, 8],
            [0x28, 4],
            [0x2C, 4],
            [0x30, 8],
            [0x38, 8],
        ]
        if arch == "0x1":
            arch_specfic_arr = x86_SCTNHDR_values
        else:
            arch_specfic_arr = x64_SCTNHDR_values
        for arr in arch_specfic_arr:
            arr[0] += sectnhdr_offset + sectnhdr_size * entry_number
        return arch_specfic_arr

    def set_type(self):
        if self.sh_type in type_dict:
            self.sh_type = type_dict[self.sh_type]

    def set_permissions(self):
        if self.sh_flags in flag_dict:
            self.sh_flags = flag_dict[self.sh_flags]

    def set_size(self):
        if self.sh_size != "unset":
            self.sh_size = self.sh_size + " ({} bytes)".format(int(self.sh_size, 16))

    def set_offset(self):
        if self.sh_offset != "unset":
            self.sh_offset = self.sh_offset + " ({} bytes into this file)".format(int(self.sh_offset, 16))

    def set_strings_in_sctnhdr(self):
        self.set_type()
        self.set_permissions()
        self.set_size()
        self.set_offset()

    def parse_output(self):
        header = ["FOUND SECTION HEADER"]
        data = [(k, v) for k, v in self.__dict__.items()]
        print(tabulate(data, header))
        print("------------  --------------------------------------------")
