import ElfHdr
import mmap

class ElfSegmentTable:

    def __init__(self, ehdr: 'ElfHdr'):
        self._class = ehdr.get_class()
        self._offset = ehdr.get_phoff()
        self._num = ehdr.get_phnum()
        self._entsize = ehdr.get_phentsize()
        self._content = None
        #self._segments = []

    def parse(self, mm: 'mmap.mmap'):
        self._content = mm[self.offset:self.offset+self.size]

    def __bool__(self):
        return bool(self.size)
        #return bool(self._segments)

    #def __getitem__(self, item) -> 'ElfSegment':
    #    return self._segments[item]

    def __repr__(self):
        return "SEGMENT TABLE"

    #@property
    #def segments(self):
    #    return self._segments

    @property
    def offset(self):
        return self._offset

    @property
    def num(self):
        return self._num

    @property
    def content(self):
        return self._content

    @property
    def entsize(self):
        return self._entsize

    @property
    def size(self):
        return self._num * self._entsize


class ElfSegment:

    def __init__(self, elfclass: str):
        self._class = elfclass

        self.p_type = None      # segment type
        self.p_offset = None    # segment file offset
        self.p_vaddr = None     # segment virtual address
        self.p_paddr = None     # segment physical address
        self.p_filesz = None    # segment size in file
        self.p_memsz = None     # segment size in memory
        self.p_flags = None     # segment flags
        self.p_align = None     # segment alignment

    def parse(self, mm: 'mmap.mmap', offset: int):
        mm.seek(offset)

        self.p_type = mm.read(4)
        if self._class == 'ELF32':
            self.p_offset = mm.read(4)
            self.p_vaddr = mm.read(4)
            self.p_paddr = mm.read(4)
            self.p_filesz = mm.read(4)
            self.p_memsz = mm.read(4)
            self.p_flags = mm.read(4)
            self.p_align = mm.read(4)
        else:
            self.p_flags = mm.read(4)
            self.p_offset = mm.read(8)
            self.p_vaddr = mm.read(8)
            self.p_paddr = mm.read(8)
            self.p_filesz = mm.read(8)
            self.p_memsz = mm.read(8)
            self.p_align = mm.read(8)

    def get_type(self) -> str:
        PT_NULL = 0
        PT_LOAD = 1
        PT_DYNAMIC = 2
        PT_INTERP = 3
        PT_NOTE = 4
        PT_SHLIB = 5
        PT_PHDR = 6
        PT_TLS = 7
        #PT_NUM = 8
        PT_LOOS = 0x60000000
        PT_GNU_EH_FRAME = 0x6474e550
        PT_GNU_STACK = 0x6474e551
        PT_GNU_RELRO = 0x6474e552
        PT_LOSUNW = 0x6fffff
        PT_SUNWBSS = 0x6ffffffa
        PT_SUNWSTACK = 0x6ffffffb
        PT_HISUNW = 0x6fffff
        PT_HIOS = 0x6fffffff
        PT_LOPROC = 0x70000000
        PT_HIPROC = 0x7fffffff

        return {
            PT_NULL: 'NULL',                # "Program header table entry unused",
            PT_LOAD: 'LOAD',                # '"Loadable program segment",
            PT_DYNAMIC: 'DYNAMIC',          # "Dynamic linking information",
            PT_INTERP: 'INTERP',            # "Program interpreter",
            PT_NOTE: 'NOTE',                # "Auxiliary information",
            PT_SHLIB: 'SHLIB',              # "Reserved",
            PT_PHDR: 'PHDR',                # "Entry for header table itself",
            PT_TLS: 'TLS',                  # '"Thread-local storage segment",
            # PT_NUM: "Number of defined types",
            PT_LOOS: 'LOOS',                    # "Start of OS-specific",
            PT_GNU_EH_FRAME: 'GNU_EH_FRAME',    # "GCC .eh_frame_hdr segment",
            PT_GNU_STACK: 'GNU_STACK',          # "Indicates stack executability",
            PT_GNU_RELRO: 'GNU_RELRO',          # "Read-only after relocation",
            PT_LOSUNW: 'LOSUNW',
            PT_SUNWBSS: 'SUNWBSS',              # "Sun Specific segment",
            PT_SUNWSTACK: 'SUNWSTACK',          # "Stack segment",
            PT_HISUNW: 'HISUNW',
            PT_HIOS: 'HIOS',                    # "End of OS-specific",
            PT_LOPROC: 'LOPROC',                # "Start of processor-specific",
            PT_HIPROC: 'HIPROC',                # "End of processor-specific"
        }.get(int.from_bytes(self.p_type, 'little'), 'Other')

    @property
    def offset(self) -> int:
        return int.from_bytes(self.p_offset, 'little')

    def get_offset(self) -> int:
        return int.from_bytes(self.p_offset, 'little')

    def get_vaddr(self) -> int:
        return int.from_bytes(self.p_vaddr, 'little')

    def get_paddr(self) -> int:
        return int.from_bytes(self.p_paddr, 'little')

    def get_filesz(self) -> int:
        return int.from_bytes(self.p_filesz, 'little')

    def get_memsz(self) -> int:
        return int.from_bytes(self.p_memsz, 'little')

    def get_flags(self) -> str:
        PF_X = 1
        PF_W = 2
        PF_R = 4
        PF_MASKOS = 0x0ff00000
        PF_MASKPROC = 0xf0000000

        flags = int.from_bytes(self.p_flags, 'little')
        s = ''
        s = s + 'R' if flags & PF_R else s + ' '
        s = s + 'W' if flags & PF_W else s + ' '
        s = s + 'E' if flags & PF_X else s + ' '
        return s

    def get_align(self) -> int:
        return int.from_bytes(self.p_align, 'little')

    def __str__(self):
        s  = 'Program header\n'
        s += '---\n'
        s += 'Type:     ' + self.get_type() + '\n'
        padding = 8 if self._class == 'ELF32' else 16
        s += 'Offset:   ' + '0x{num:0{width}x}'.format(num=self.get_offset(), width=padding) + '\n'
        s += 'VirtAddr: ' + '0x{num:0{width}x}'.format(num=self.get_vaddr(), width=padding) + '\n'
        s += 'PhysAddr: ' + '0x{num:0{width}x}'.format(num=self.get_paddr(), width=padding) + '\n'
        s += 'FileSiz:  ' + str(self.get_filesz()) + ' (bytes)\n'
        s += 'MemSiz:   ' + str(self.get_memsz()) + ' (bytes)\n'
        s += 'Flags:    ' + self.get_flags() + '\n'
        s += 'Align:    ' + str(self.get_align()) + '\n'
        return s
