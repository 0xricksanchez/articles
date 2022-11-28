type_dict = {
    "0x0": "PT_NULL",
    "0x1": "PT_LOAD",
    "0x2": "PT_DYNAMIC",
    "0x3": "PT_INTERP",
    "0x4": "PT_NOTE",
    "0x5": "PT_SHLIB",
    "0x6": "PT_PHDR",
    "0x60000000": "PT_LOOS",
    "0x6fffffff": "PT_HIOS",
    "0x70000000": "PT_LOPROC",
    "0x7fffffff": "PT_HIPROC",
}

flag_dict = {
    "0x0": "all access denied",
    "0x1": "execute only",
    "0x2": "write only",
    "0x3": "write, execute",
    "0x4": "read only",
    "0x5": "read, execute",
    "0x6": "read, write",
    "0x7": "read, write, execute",
}
