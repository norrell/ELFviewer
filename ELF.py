import mmap
from typing import List

class ELF:

    def __init__(self, filename: str):
        self._f = open(filename, 'rb')
        self._mm = mmap.mmap(self._f.fileno(), 0, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ)

        self.ehdr = ElfHdr()
        self.ehdr.parse(self._mm)

        self.phdrs = self.get_phdr_table()
        self.shdrs = self.get_shdr_table()

    def get_phdr_table(self) -> List['ElfProgHdr']:
        phdrs = []
        for offset in range(self.ehdr.get_phoff(),
                            self.ehdr.get_phoff() + self.ehdr.get_phnum() * self.ehdr.get_phentsize(),
                            self.ehdr.get_phentsize()):
            phdr = ElfProgHdr(self.ehdr.get_class())
            phdr.parse(self._mm, offset)
            phdrs.append(phdr)
        return phdrs

    def get_shdr_table(self)-> List['ElfSectHdr']:
        shdrs = []
        for offset in range(self.ehdr.get_shoff(),
                            self.ehdr.get_shoff() + self.ehdr.get_shnum() * self.ehdr.get_shentsize(),
                            self.ehdr.get_shentsize()):
            shdr = ElfSectHdr(self.ehdr.get_class())
            shdr.parse(self._mm, offset)
            shdrs.append(shdr)
        return shdrs

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._mm.close()
        self._f.close()


class ElfHdr:
    ELFMAGIC = bytes([0x7f, 0x45, 0x4c, 0x46])

    ELFCLASSNONE = 0
    ELFCLASS32 = 1
    ELFCLASS64 = 2

    def __init__(self):
        '''
        see /usr/include/elf.h
        the only real difference between 32 and 64 bits is
        Elf32_Addr -> uint32_t vs Elf64_Addr -> uint64_t
        Elf32_Off -> uint32_t  vs Elf64_Off -> uint64_t
        '''
        self.e_ident = None         # magic number and other info, [16 x uint8_t]
        self.e_type = None          # object file type, uint16_t
        self.e_machine = None       # architecture, uint16_t
        self.e_version = None       # object file version, uint32_t
        self.e_entry = None         # entry point virtual address, ElfXX_Addr
        self.e_phoff = None         # program header table file offset, ElfXX_Off
        self.e_shoff = None         # section header table file offset, ElfXX_Off
        self.e_flags = None         # processor-specific flags, uint32_t
        self.e_ehsize = None        # ELF header size in bytes, uint16_t
        self.e_phentsize = None     # program header table entry size, uint16_t
        self.e_phnum = None         # program header table entry count, uint16_t
        self.e_shentsize = None     # section header table entry size, uint16_t
        self.e_shnum = None         # section header table entry count, uint16_t
        self.e_shstrndx = None      # section header string table index, uint16_t

    def parse(self, mm: 'mmap.mmap'):
        mm.seek(0)

        self.e_ident = mm.read(16)
        if self.get_magic_number() != ElfHdr.ELFMAGIC:
            raise ValueError('not an ELF file')

        self.e_type = mm.read(2)
        self.e_machine = mm.read(2)
        self.e_version = mm.read(4)

        if self.get_class() == '32':
            self.e_entry = mm.read(4)
            self.e_phoff = mm.read(4)
            self.e_shoff = mm.read(4)
        elif self.get_class() == '64':
            self.e_entry = mm.read(8)
            self.e_phoff = mm.read(8)
            self.e_phoff = mm.read(8)
        else:
            raise ValueError('invalid class')

        self.e_ehsize = mm.read(2)
        self.e_phentsize = mm.read(2)
        self.e_phnum = mm.read(2)
        self.e_shentsize = mm.read(2)
        self.e_shnum = mm.read(2)
        self.e_shstrndx = mm.read(2)

    def get_magic_number(self):
        return self.e_ident[:3]

    def get_class(self):
        return {
            ElfHdr.ELFCLASSNONE: '',
            ElfHdr.ELFCLASS32: '32',
            ElfHdr.ELFCLASS64: '64'
        }.get(self.e_ident[4], '')

    def get_data_encoding(self):
        return self.e_ident[5]

    def get_version(self):
        return self.e_ident[6]

    def get_ABI(self):
        return self.e_ident[7]

    def get_ABI_version(self):
        return self.e_ident[8]

    def get_phoff(self):
        return int.from_bytes(self.e_phoff, byteorder='little')

    def get_phnum(self):
        return int.from_bytes(self.e_phnum, byteorder='little')

    def get_phentsize(self):
        return int.from_bytes(self.e_phentsize, byteorder='little')

    def get_shoff(self):
        return int.from_bytes(self.e_shoff, byteorder='little')

    def get_shnum(self):
        return int.from_bytes(self.e_shnum, byteorder='little')

    def get_shentsize(self):
        return int.from_bytes(self.e_shentsize, byteorder='little')


class ElfProgHdr:
    '''
    typedef struct {
       uint32_t   p_type;
       Elf32_Off  p_offset;
       Elf32_Addr p_vaddr;
       Elf32_Addr p_paddr;
       uint32_t   p_filesz;
       uint32_t   p_memsz;
       uint32_t   p_flags;
       uint32_t   p_align;
    } Elf32_Phdr;

    typedef struct {
       uint32_t   p_type;
       uint32_t   p_flags;
       Elf64_Off  p_offset;
       Elf64_Addr p_vaddr;
       Elf64_Addr p_paddr;
       uint64_t   p_filesz;
       uint64_t   p_memsz;
       uint64_t   p_align;
    } Elf64_Phdr;
    '''

    def __init__(self, elfclass: str):
        if elfclass not in ('32', '64'):
            raise ValueError('invalid ELF class')

        self._class = elfclass

        self.p_type = None      # Segment type, uint32_t
        self.p_offset = None    # Segment file offset, uint32_t or uint64_t
        self.p_vaddr = None     # Segment virtual address, uint32_t or uint64_t
        self.p_paddr = None     # Segment physical address, uint32_t or uint64_t
        self.p_filesz = None    # Segment size in file, uint32_t or uint64_t
        self.p_memsz = None     # Segment size in memory, uint32_t or uint64_t
        self.p_flags = None     # Segment flags, uint32_t or uint64_t
        self.p_align = None     # Segment alignment, uint32_t or uint64_t

    def parse(self, mm: 'mmap.mmap', offset: int):
        mm.seek(offset)

        self.p_type = mm.read(4)
        if self._class == '32':
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


class ElfSectHdr:
    '''
    typedef struct {
       uint32_t   sh_name;
       uint32_t   sh_type;
       uint32_t   sh_flags;
       Elf32_Addr sh_addr;
       Elf32_Off  sh_offset;
       uint32_t   sh_size;
       uint32_t   sh_link;
       uint32_t   sh_info;
       uint32_t   sh_addralign;
       uint32_t   sh_entsize;
    } Elf32_Shdr;

    typedef struct {
       uint32_t   sh_name;
       uint32_t   sh_type;
       uint64_t   sh_flags;
       Elf64_Addr sh_addr;
       Elf64_Off  sh_offset;
       uint64_t   sh_size;
       uint32_t   sh_link;
       uint32_t   sh_info;
       uint64_t   sh_addralign;
       uint64_t   sh_entsize;
    } Elf64_Shdr;
    '''
    def __init__(self, elfclass):
        if elfclass not in ('32', '64'):
            raise ValueError('invalid ELF class')

        self._class = elfclass

        self.sh_name = None
        self.sh_type = None
        self.sh_flags = None
        self.sh_addr = None
        self.sh_offset = None
        self.sh_size = None
        self.sh_link = None
        self.sh_info = None
        self.sh_addralign = None
        self.sh_entsize = None

    def parse(self, mm: 'mmap.mmap', offset):
        mm.seek(offset)

        self.sh_name = mm.read(4)
        self.sh_type = mm.read(4)
        if self._class == '32':
            self.sh_flags = mm.read(4)
            self.sh_addr = mm.read(4)
            self.sh_offset = mm.read(4)
            self.sh_size = mm.read(4)
            self.sh_link = mm.read(4)
            self.sh_info = mm.read(4)
            self.sh_addralign = mm.read(4)
            self.sh_entsize = mm.read(4)
        else:
            self.sh_flags = mm.read(8)
            self.sh_addr = mm.read(8)
            self.sh_offset = mm.read(8)
            self.sh_size = mm.read(8)
            self.sh_link = mm.read(4)
            self.sh_info = mm.read(4)
            self.sh_addralign = mm.read(8)
            self.sh_entsize = mm.read(8)
