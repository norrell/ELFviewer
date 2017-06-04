import ElfHdr
import mmap
from util import hexdump

class ElfSectionTable:

    def __init__(self, ehdr: 'ElfHdr'):
        self._class = ehdr.get_class()
        self._offset = ehdr.get_shoff()
        self._num = ehdr.get_shnum()
        self._entsize = ehdr.get_shentsize()
        self._strndx = ehdr.get_shstrndx()

        self._content = None
        #self._sections = []

    def parse(self, mm: 'mmap.mmap'):
        self._content = mm[self.offset:self.offset+self.size]

    #def __bool__(self):
    #    return bool(self._sections)
    def __bool__(self):
        return bool(self.size)

    #def __getitem__(self, item):
    #    return self._sections[item]

    def __repr__(self):
        return '<SECTION TABLE>'

    @property
    def elfclass(self):
        return self._class

    @property
    def offset(self):
        return self._offset

    @property
    def num(self):
        return self._num

    @property
    def entsize(self):
        return self._entsize

    @property
    def size(self):
        return self._num * self._entsize

    @property
    def strndx(self):
        return self._strndx

    #@property
    #def sections(self):
    #    return self._sections


class ElfSection:

    def __init__(self, elfclass: str):
        self._class = elfclass

        self._name = ''      # at section creation, the name cannot be known
        self._shname = None  # since the sh_name field first needs to be parsed
        self._type = None
        self._flags = None
        self._address = None
        self._offset = None
        self._size = None
        self._link = None
        self._info = None
        self._addralign = None
        self._entsize = None
        self._content = None

    def parse(self, mm: 'mmap.mmap', offset: int, names: bytes = None):
        mm.seek(offset)
        sh_name = mm.read(4)
        sh_type = mm.read(4)
        if self._class == 'ELF32':
            sh_flags = mm.read(4)
            sh_addr = mm.read(4)
            sh_offset = mm.read(4)
            sh_size = mm.read(4)
            sh_link = mm.read(4)
            sh_info = mm.read(4)
            sh_addralign = mm.read(4)
            sh_entsize = mm.read(4)
        else:
            sh_flags = mm.read(8)
            sh_addr = mm.read(8)
            sh_offset = mm.read(8)
            sh_size = mm.read(8)
            sh_link = mm.read(4)
            sh_info = mm.read(4)
            sh_addralign = mm.read(8)
            sh_entsize = mm.read(8)

        self._shname = int.from_bytes(sh_name, 'little')
        if names:
            self._name = self.parse_name(names, self._shname)
        self._type = ElfSection.parse_type(int.from_bytes(sh_type, 'little'))
        self._flags = ElfSection.parse_flags(int.from_bytes(sh_flags, 'little'))
        self._address = int.from_bytes(sh_addr, 'little')
        self._offset = int.from_bytes(sh_offset, 'little')
        self._size = int.from_bytes(sh_size, 'little')
        self._link = sh_link  # ?
        self._info = sh_info  # ?
        self._addralign = int.from_bytes(sh_addralign, 'little')
        self._entsize = int.from_bytes(sh_entsize, 'little')
        self._content = mm[self._offset:self._offset+self._size]

    def parse_name(self, section_names: bytes, offset: int) -> str:
        name =''
        i = 0
        while True:
            ch = section_names[offset + i]
            if ch == 0x00:
                break
            else:
                name += chr(ch)
                i += 1
        return name

    def __str__(self):
        s  = 'Section ' + self.name + '\n'
        s += '---\n'
        s += 'Type:     ' + self.type + '\n'
        s += 'Flags:    ' + self.flags + '\n'
        padding = 8 if self._class == 'ELF32' else 16
        s += 'Offset:   ' + '0x{num:0{width}x}'.format(num=self.offset, width=padding) + '\n'
        s += 'Content:\n' + hexdump(self.content, self.offset) + '\n'
        return s

    @property
    def name(self) -> str:
        return self._name

    @property
    def type(self) -> str:
        return self._type

    @property
    def flags(self) -> str:
        return self._flags

    @property
    def address(self) -> int:
        return self._address

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def size(self) -> int:
        return self._size

    @property
    def link(self) -> int:
        return self._link

    @property
    def info(self):
        return self._info

    @property
    def addralign(self) -> int:
        return self._addralign

    @property
    def entsize(self) -> int:
        return self._entsize

    @property
    def content(self) -> bytes:
        return self._content

    @staticmethod
    def parse_flags(flags: int) -> str:
        SHF_WRITE = (1 << 0)
        SHF_ALLOC = (1 << 1)
        SHF_EXECINSTR = (1 << 2)
        SHF_MERGE = (1 << 4)
        SHF_STRINGS = (1 << 5)
        SHF_INFO_LINK = (1 << 6)
        SHF_LINK_ORDER = (1 << 7)
        SHF_OS_NONCONFORMING = (1 << 8)
        SHF_GROUP = (1 << 9)
        SHF_TLS = (1 << 10)
        SHF_COMPRESSED = (1 << 11)
        SHF_MASKOS = 0x0ff00000
        SHF_MASKPROC = 0xf0000000
        SHF_ORDERED = (1 << 30)
        SHF_EXCLUDE = (1 << 31)

        s = ''
        if flags & SHF_WRITE: s += 'W'
        if flags & SHF_ALLOC: s += 'A'
        if flags & SHF_EXECINSTR: s += 'X'
        if flags & SHF_MERGE: s += 'M'
        if flags & SHF_STRINGS: s += 'S'
        if flags & SHF_INFO_LINK: s += 'I'
        if flags & SHF_LINK_ORDER: s += 'L'
        if flags & SHF_OS_NONCONFORMING: s += 'O'
        if flags & SHF_GROUP: s += 'G'
        if flags & SHF_TLS: s += 'T'
        if flags & SHF_COMPRESSED: s += 'C'
        if flags & SHF_MASKOS: s += 'o'
        if flags & SHF_MASKPROC: s += 'p'
        if flags & SHF_EXCLUDE: s += 'E'
        return s

    @staticmethod
    def parse_type(code: int) -> str:
        SHT_LOPROC = 0x70000000
        SHT_HIPROC = 0x7fffffff
        SHT_LOUSER = 0x80000000
        SHT_HIUSER = 0x8fffffff

        if SHT_LOUSER <= code <= SHT_HIUSER:
            return 'Application-specific'

        if SHT_LOPROC <= code <= SHT_HIPROC:
            return 'Processor-specific'

        SHT_LOOS = 0x60000000  # Start OS-specific.

        SHT_GNU_ATTRIBUTES = 0x6ffffff5  # Object attributes.
        SHT_GNU_HASH = 0x6ffffff6  # GNU-style hash table.
        SHT_GNU_LIBLIST = 0x6ffffff7  # Prelink library list.
        SHT_CHECKSUM = 0x6ffffff8  # Checksum for DSO content.

        SHT_LOSUNW = 0x6ffffffa  # Sun-specific low bound.

        SHT_SUNW_move = 0x6ffffffa
        SHT_SUNW_COMDAT = 0x6ffffffb
        SHT_SUNW_syminfo = 0x6ffffffc
        SHT_GNU_verdef = 0x6ffffffd  # Version definition section.
        SHT_GNU_verneed = 0x6ffffffe  # Version needs section.
        SHT_GNU_versym = 0x6fffffff  # Version symbol table.

        SHT_HISUNW = 0x6fffffff  # Sun-specific high bound.

        SHT_HIOS = 0x6fffffff  # End OS-specific type

        if SHT_LOSUNW <= code <= SHT_HISUNW:
            return {
                SHT_SUNW_move: 'SUNW_move',
                SHT_SUNW_COMDAT: 'SUNW_COMDAT',
                SHT_SUNW_syminfo: 'SUNW_SYMINFO',
                SHT_GNU_verdef: 'GNU_VERDEF',
                SHT_GNU_verneed: 'GNU_VERNEEd',
                SHT_GNU_versym: 'GNU_VERSYM',
            }.get(code, 'Sun-specific')

        if SHT_LOOS <= code <= SHT_HIOS:
            return {
                SHT_GNU_ATTRIBUTES: 'GNU_ATTRIBUTES',
                SHT_GNU_HASH: 'GNU_HASH',
                SHT_GNU_LIBLIST: 'GNU_LIBLIST',
                SHT_CHECKSUM: 'CHECKSUM'
            }.get(code, 'OS-specific')

        SHT_NULL = 0
        SHT_PROGBITS = 1
        SHT_SYMTAB = 2
        SHT_STRTAB = 3
        SHT_RELA = 4
        SHT_HASH = 5
        SHT_DYNAMIC = 6
        SHT_NOTE = 7
        SHT_NOBITS = 8
        SHT_REL = 9
        SHT_SHLIB = 10
        SHT_DYNSYM = 11
        SHT_INIT_ARRAY = 14
        SHT_FINI_ARRAY = 15
        SHT_PREINIT_ARRAY = 16
        SHT_GROUP = 17
        SHT_SYMTAB_SHNDX = 18

        return {
            SHT_NULL: 'NULL',
            SHT_PROGBITS: 'PROGBITS',
            SHT_SYMTAB: 'SYMTAB',
            SHT_STRTAB: 'STRTAB',
            SHT_RELA: 'RELA',
            SHT_HASH: 'HASH',
            SHT_DYNAMIC: 'DYNAMIC',
            SHT_NOTE: 'NOTE',
            SHT_NOBITS: 'NOBITS',
            SHT_REL: 'REL',
            SHT_SHLIB: 'SHLIB',
            SHT_DYNSYM: 'DYNSYM',
            SHT_INIT_ARRAY: 'INIT_ARRAY',
            SHT_FINI_ARRAY: 'FINI_ARRAY',
            SHT_PREINIT_ARRAY: 'PREINIT_ARRAY',
            SHT_GROUP: 'GROUP',
            SHT_SYMTAB_SHNDX: 'SYMTAB_SHNDX'
        }.get(code, 'other')
