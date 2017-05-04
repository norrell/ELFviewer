import mmap
from typing import List
import util

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
        start = self.ehdr.get_phoff()
        count = self.ehdr.get_phnum()
        size = self.ehdr.get_phentsize()
        end = start + count * size
        for offset in range(start, end, size):
            phdr = ElfProgHdr(self.ehdr.get_class())
            phdr.parse(self._mm, offset)
            phdrs.append(phdr)
        return phdrs

    def get_shdr_table(self)-> List['ElfSectHdr']:
        shdrs = []
        start = self.ehdr.get_shoff()
        count = self.ehdr.get_shnum()
        size = self.ehdr.get_shentsize()
        end = start + count * size
        for offset in range(start, end, size):
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
    ELFMAGIC = bytes([0x7f, ord('E'), ord('L'), ord('F')])

    def __init__(self):
        '''
        typedef struct {
           unsigned char e_ident[EI_NIDENT];
           uint16_t      e_type;
           uint16_t      e_machine;
           uint32_t      e_version;
           ElfN_Addr     e_entry;
           ElfN_Off      e_phoff;
           ElfN_Off      e_shoff;
           uint32_t      e_flags;
           uint16_t      e_ehsize;
           uint16_t      e_phentsize;
           uint16_t      e_phnum;
           uint16_t      e_shentsize;
           uint16_t      e_shnum;
           uint16_t      e_shstrndx;
        } ElfN_Ehdr;
        '''
        self.e_ident = None         # magic number and other info
        self.e_type = None          # object file type
        self.e_machine = None       # architecture
        self.e_version = None       # object file version
        self.e_entry = None         # entry point virtual address
        self.e_phoff = None         # program header table file offset
        self.e_shoff = None         # section header table file offset
        self.e_flags = None         # processor-specific flags,
        self.e_ehsize = None        # ELF header size in bytes,
        self.e_phentsize = None     # program header table entry size
        self.e_phnum = None         # program header table entry count
        self.e_shentsize = None     # section header table entry size
        self.e_shnum = None         # section header table entry count
        self.e_shstrndx = None      # section header string table index

    def parse(self, mm: 'mmap.mmap'):
        mm.seek(0)

        self.e_ident = mm.read(16)
        magic = self.get_magic_number()
        if self.get_magic_number() != ElfHdr.ELFMAGIC:
            raise ValueError('not an ELF file')

        self.e_type = mm.read(2)
        self.e_machine = mm.read(2)
        self.e_version = mm.read(4)

        if self.get_class() == 'ELF32':
            self.e_entry = mm.read(4)
            self.e_phoff = mm.read(4)
            self.e_shoff = mm.read(4)
        elif self.get_class() == 'ELF64':
            self.e_entry = mm.read(8)
            self.e_phoff = mm.read(8)
            self.e_shoff = mm.read(8)
        else:
            raise ValueError('invalid class')

        self.e_flags = mm.read(4)
        self.e_ehsize = mm.read(2)
        self.e_phentsize = mm.read(2)
        self.e_phnum = mm.read(2)
        self.e_shentsize = mm.read(2)
        self.e_shnum = mm.read(2)
        self.e_shstrndx = mm.read(2)

    def get_magic_number(self) -> bytes:
        return self.e_ident[:4]

    def get_class(self) -> str:
        ELFCLASSNONE = 0
        ELFCLASS32 = 1
        ELFCLASS64 = 2

        return {
            ELFCLASSNONE: '',
            ELFCLASS32: 'ELF32',
            ELFCLASS64: 'ELF64'
        }.get(self.e_ident[4], '')

    def get_type(self) -> str:
        ET_NONE = 0
        ET_REL = 1
        ET_EXEC = 2
        ET_DYN = 3
        ET_CORE = 4

        return {
            ET_NONE: 'NONE (Unknown type)',
            ET_REL: 'REL (Relocatable file)',
            ET_EXEC: 'EXEC (Executable file',
            ET_DYN: 'DYN (Shared object)',
            ET_CORE: 'CORE (Core file)'
        }.get(int.from_bytes(self.e_type, 'little'), 'OTHER')

    def get_machine(self) -> str:
        EM_NONE = 0
        EM_M32 = 1
        EM_SPARC = 2
        EM_386 = 3
        EM_68K = 4
        EM_88K = 5
        EM_IAMCU = 6
        EM_860 = 7
        EM_MIPS = 8
        EM_S370 = 9
        EM_MIPS_RS3_LE = 10

        EM_PARISC = 15

        EM_VPP500 = 17
        EM_SPARC32PLUS = 18
        EM_960 = 19
        EM_PPC = 20
        EM_PPC64 = 21
        EM_S390 = 22
        EM_SPU = 23

        EM_V800 = 36
        EM_FR20 = 37
        EM_RH32 = 38
        EM_RCE = 39
        EM_ARM = 40
        EM_FAKE_ALPHA = 41
        EM_SH = 42
        EM_SPARCV9 = 43
        EM_TRICORE = 44
        EM_ARC = 45
        EM_H8_300 = 46
        EM_H8_300H = 47
        EM_H8S = 48
        EM_H8_500 = 49
        EM_IA_64 = 50
        EM_MIPS_X = 51
        EM_COLDFIRE = 52
        EM_68HC12 = 53
        EM_MMA = 54
        EM_PCP = 55
        EM_NCPU = 56
        EM_NDR1 = 57
        EM_STARCORE = 58
        EM_ME16 = 59
        EM_ST100 = 60
        EM_TINYJ = 61
        EM_X86_64 = 62
        EM_PDSP = 63
        EM_PDP10 = 64
        EM_PDP11 = 65
        EM_FX66 = 66
        EM_ST9PLUS = 67
        EM_ST7 = 68
        EM_68HC16 = 69
        EM_68HC11 = 70
        EM_68HC08 = 71
        EM_68HC05 = 72
        EM_SVX = 73
        EM_ST19 = 74
        EM_VAX = 75
        EM_CRIS = 76
        EM_JAVELIN = 77
        EM_FIREPATH = 78
        EM_ZSP = 79
        EM_MMIX = 80
        EM_HUANY = 81
        EM_PRISM = 82
        EM_AVR = 83
        EM_FR30 = 84
        EM_D10V = 85
        EM_D30V = 86
        EM_V850 = 87
        EM_M32R = 88
        EM_MN10300 = 89
        EM_MN10200 = 90
        EM_PJ = 91
        EM_OPENRISC = 92
        EM_ARC_COMPACT = 93
        EM_XTENSA = 94
        EM_VIDEOCORE = 95
        EM_TMM_GPP = 96
        EM_NS32K = 97
        EM_TPC = 98
        EM_SNP1K = 99
        EM_ST200 = 100
        EM_IP2K = 101
        EM_MAX = 102
        EM_CR = 103
        EM_F2MC16 = 104
        EM_MSP430 = 105
        EM_BLACKFIN = 106
        EM_SE_C33 = 107
        EM_SEP = 108
        EM_ARCA = 109
        EM_UNICORE = 110
        EM_EXCESS = 111
        EM_DXP = 112
        EM_ALTERA_NIOS2 = 113
        EM_CRX = 114
        EM_XGATE = 115
        EM_C166 = 116
        EM_M16C = 117
        EM_DSPIC30F = 118
        EM_CE = 119
        EM_M32C = 120

        EM_TSK3000 = 131
        EM_RS08 = 132
        EM_SHARC = 133
        EM_ECOG2 = 134
        EM_SCORE7 = 135
        EM_DSP24 = 136
        EM_VIDEOCORE3 = 137
        EM_LATTICEMICO32 = 138
        EM_SE_C17 = 139
        EM_TI_C6000 = 140
        EM_TI_C2000 = 141
        EM_TI_C5500 = 142
        EM_TI_ARP32 = 143
        EM_TI_PRU = 144

        EM_MMDSP_PLUS = 160
        EM_CYPRESS_M8C = 161
        EM_R32C = 162
        EM_TRIMEDIA = 163
        EM_QDSP6 = 164
        EM_8051 = 165
        EM_STXP7X = 166
        EM_NDS32 = 167
        EM_ECOG1X = 168
        EM_MAXQ30 = 169
        EM_XIMO16 = 170
        EM_MANIK = 171
        EM_CRAYNV2 = 172
        EM_RX = 173
        EM_METAG = 174
        EM_MCST_ELBRUS = 175
        EM_ECOG16 = 176
        EM_CR16 = 177
        EM_ETPU = 178
        EM_SLE9X = 179
        EM_L10M = 180
        EM_K10M = 181

        EM_AARCH64 = 183

        EM_AVR32 = 185
        EM_STM8 = 186
        EM_TILE64 = 187
        EM_TILEPRO = 188
        EM_MICROBLAZE = 189
        EM_CUDA = 190
        EM_TILEGX = 191
        EM_CLOUDSHIELD = 192
        EM_COREA_1ST = 193
        EM_COREA_2ND = 194
        EM_ARC_COMPACT2 = 195
        EM_OPEN8 = 196
        EM_RL78 = 197
        EM_VIDEOCORE5 = 198
        EM_78KOR = 199
        EM_56800EX = 200
        EM_BA1 = 201
        EM_BA2 = 202
        EM_XCORE = 203
        EM_MCHP_PIC = 204

        EM_KM32 = 210
        EM_KMX32 = 211
        EM_EMX16 = 212
        EM_EMX8 = 213
        EM_KVARC = 214
        EM_CDP = 215
        EM_COGE = 216
        EM_COOL = 217
        EM_NORC = 218
        EM_CSR_KALIMBA = 219
        EM_Z80 = 220
        EM_VISIUM = 221
        EM_FT32 = 222
        EM_MOXIE = 223
        EM_AMDGPU = 224

        EM_RISCV = 243

        EM_BPF = 247

        EM_NUM = 2

        return {
            EM_NONE: "No machine",
            EM_M32: "AT&T WE 32100",
            EM_SPARC: "SUN SPARC",
            EM_386: "Intel 80386",
            EM_68K: "Motorola m68k family",
            EM_88K: "Motorola m88k family",
            EM_IAMCU: "Intel MCU",
            EM_860: "Intel 80860",
            EM_MIPS: "MIPS R3000 big-endian",
            EM_S370: "IBM System/370",
            EM_MIPS_RS3_LE: "MIPS R3000 little-endian",
            EM_PARISC: "HPPA",
            EM_VPP500: "Fujitsu VPP500",
            EM_SPARC32PLUS: "Sun's \"v8plus\"",
            EM_960: "Intel 80960",
            EM_PPC: "PowerPC",
            EM_PPC64: "PowerPC 64-bit",
            EM_S390: "IBM S390",
            EM_SPU: "IBM SPU/SPC",
            EM_V800: "NEC V800 series",
            EM_FR20: "Fujitsu FR20",
            EM_RH32: "TRW RH-32",
            EM_RCE: "Motorola RCE",
            EM_ARM: "ARM",
            EM_FAKE_ALPHA: "Digital Alpha",
            EM_SH: "Hitachi SH",
            EM_SPARCV9: "SPARC v9 64-bit",
            EM_TRICORE: "Siemens Tricore",
            EM_ARC: "Argonaut RISC Core",
            EM_H8_300: "Hitachi H8/300",
            EM_H8_300H: "Hitachi H8/300H",
            EM_H8S: "Hitachi H8S",
            EM_H8_500: "Hitachi H8/500",
            EM_IA_64: "Intel Merced",
            EM_MIPS_X: "Stanford MIPS-X",
            EM_COLDFIRE: "Motorola Coldfire",
            EM_68HC12: "Motorola M68HC12",
            EM_MMA: "Fujitsu MMA Multimedia Accelerator",
            EM_PCP: "Siemens PCP",
            EM_NCPU: "Sony nCPU embeeded RISC",
            EM_NDR1: "Denso NDR1 microprocessor",
            EM_STARCORE: "Motorola Start*Core processor",
            EM_ME16: "Toyota ME16 processor",
            EM_ST100: "STMicroelectronic ST100 processor",
            EM_TINYJ: "Advanced Logic Corp. Tinyj emb.fam",
            EM_X86_64: "AMD x86-64 architecture",
            EM_PDSP: "Sony DSP Processor",
            EM_PDP10: "Digital PDP-10",
            EM_PDP11: "Digital PDP-11",
            EM_FX66: "Siemens FX66 microcontroller",
            EM_ST9PLUS: "STMicroelectronics ST9+ 8/16 mc",
            EM_ST7: "STmicroelectronics ST7 8 bit mc",
            EM_68HC16: "Motorola MC68HC16 microcontroller",
            EM_68HC11: "Motorola MC68HC11 microcontroller",
            EM_68HC08: "Motorola MC68HC08 microcontroller",
            EM_68HC05: "Motorola MC68HC05 microcontroller",
            EM_SVX: "Silicon Graphics SVx",
            EM_ST19: "STMicroelectronics ST19 8 bit mc",
            EM_VAX: "Digital VAX",
            EM_CRIS: "Axis Communications 32-bit emb.proc",
            EM_JAVELIN: "Infineon Technologies 32-bit emb.proc",
            EM_FIREPATH: "Element 14 64-bit DSP Processor",
            EM_ZSP: "LSI Logic 16-bit DSP Processor",
            EM_MMIX: "Donald Knuth's educational 64-bit proc",
            EM_HUANY: "Harvard University machine-independent object files",
            EM_PRISM: "SiTera Prism",
            EM_AVR: "Atmel AVR 8-bit microcontroller",
            EM_FR30: "Fujitsu FR30",
            EM_D10V: "Mitsubishi D10V",
            EM_D30V: "Mitsubishi D30V",
            EM_V850: "NEC v850",
            EM_M32R: "Mitsubishi M32R",
            EM_MN10300: "Matsushita MN10300",
            EM_MN10200: "Matsushita MN10200",
            EM_PJ: "picoJava",
            EM_OPENRISC: "OpenRISC 32-bit embedded processor",
            EM_ARC_COMPACT: "ARC International ARCompact",
            EM_XTENSA: "Tensilica Xtensa Architecture",
            EM_VIDEOCORE: "Alphamosaic VideoCore",
            EM_TMM_GPP: "Thompson Multimedia General Purpose Proc",
            EM_NS32K: "National Semi. 32000",
            EM_TPC: "Tenor Network TPC",
            EM_SNP1K: "Trebia SNP 1000",
            EM_ST200: "STMicroelectronics ST200",
            EM_IP2K: "Ubicom IP2xxx",
            EM_MAX: "MAX processor",
            EM_CR: "National Semi. CompactRISC",
            EM_F2MC16: "Fujitsu F2MC16",
            EM_MSP430: "Texas Instruments msp430",
            EM_BLACKFIN: "Analog Devices Blackfin DSP",
            EM_SE_C33: "Seiko Epson S1C33 family",
            EM_SEP: "Sharp embedded microprocessor",
            EM_ARCA: "Arca RISC",
            EM_UNICORE: "PKU-Unity & MPRC Peking Uni. mc series",
            EM_EXCESS: "eXcess configurable cpu",
            EM_DXP: "Icera Semi. Deep Execution Processor",
            EM_ALTERA_NIOS2: "Altera Nios II",
            EM_CRX: "National Semi. CompactRISC CRX",
            EM_XGATE: "Motorola XGATE",
            EM_C166: "Infineon C16x/XC16x",
            EM_M16C: "Renesas M16C",
            EM_DSPIC30F: "Microchip Technology dsPIC30F",
            EM_CE: "Freescale Communication Engine RISC",
            EM_M32C: "Renesas M32C",
            EM_TSK3000: "Altium TSK3000",
            EM_RS08: "Freescale RS08",
            EM_SHARC: "Analog Devices SHARC family",
            EM_ECOG2: "Cyan Technology eCOG2",
            EM_SCORE7: "Sunplus S+core7 RISC",
            EM_DSP24: "New Japan Radio (NJR) 24-bit DSP",
            EM_VIDEOCORE3: "Broadcom VideoCore III",
            EM_LATTICEMICO32: "RISC for Lattice FPGA",
            EM_SE_C17: "Seiko Epson C17",
            EM_TI_C6000: "Texas Instruments TMS320C6000 DSP",
            EM_TI_C2000: "Texas Instruments TMS320C2000 DSP",
            EM_TI_C5500: "Texas Instruments TMS320C55x DSP",
            EM_TI_ARP32: "Texas Instruments App. Specific RISC",
            EM_TI_PRU: "Texas Instruments Prog. Realtime Unit",
            EM_MMDSP_PLUS: "STMicroelectronics 64bit VLIW DSP",
            EM_CYPRESS_M8C: "Cypress M8C",
            EM_R32C: "Renesas R32C",
            EM_TRIMEDIA: "NXP Semi. TriMedia",
            EM_QDSP6: "QUALCOMM DSP6",
            EM_8051: "Intel 8051 and variants",
            EM_STXP7X: "STMicroelectronics STxP7x",
            EM_NDS32: "Andes Tech. compact code emb. RISC",
            EM_ECOG1X: "Cyan Technology eCOG1X",
            EM_MAXQ30: "Dallas Semi. MAXQ30 mc",
            EM_XIMO16: "New Japan Radio (NJR) 16-bit DSP",
            EM_MANIK: "M2000 Reconfigurable RISC",
            EM_CRAYNV2: "Cray NV2 vector architecture",
            EM_RX: "Renesas RX",
            EM_METAG: "Imagination Tech. META",
            EM_MCST_ELBRUS: "MCST Elbrus",
            EM_ECOG16: "Cyan Technology eCOG16",
            EM_CR16: "National Semi. CompactRISC CR16",
            EM_ETPU: "Freescale Extended Time Processing Unit",
            EM_SLE9X: "Infineon Tech. SLE9X",
            EM_L10M: "Intel L10M",
            EM_K10M: "Intel K10M",
            EM_AARCH64: "ARM AARCH64",
            EM_AVR32: "Amtel 32-bit microprocessor",
            EM_STM8: "STMicroelectronics STM8",
            EM_TILE64: "Tileta TILE64",
            EM_TILEPRO: "Tilera TILEPro",
            EM_MICROBLAZE: "Xilinx MicroBlaze",
            EM_CUDA: "NVIDIA CUDA",
            EM_TILEGX: "Tilera TILE-Gx",
            EM_CLOUDSHIELD: "CloudShield",
            EM_COREA_1ST: "KIPO-KAIST Core-A 1st gen.",
            EM_COREA_2ND: "KIPO-KAIST Core-A 2nd gen.",
            EM_ARC_COMPACT2: "Synopsys ARCompact V2",
            EM_OPEN8: "Open8 RISC",
            EM_RL78: "Renesas RL78",
            EM_VIDEOCORE5: "Broadcom VideoCore V",
            EM_78KOR: "Renesas 78KOR",
            EM_56800EX: "Freescale 56800EX DSC",
            EM_BA1: "Beyond BA1",
            EM_BA2: "Beyond BA2",
            EM_XCORE: "XMOS xCORE",
            EM_MCHP_PIC: "Microchip 8-bit PIC(r)",
            EM_KM32: "KM211 KM32",
            EM_KMX32: "KM211 KMX32",
            EM_EMX16: "KM211 KMX16",
            EM_EMX8: "KM211 KMX8",
            EM_KVARC: "KM211 KVARC",
            EM_CDP: "Paneve CDP",
            EM_COGE: "Cognitive Smart Memory Processor",
            EM_COOL: "Bluechip CoolEngine",
            EM_NORC: "Nanoradio Optimized RISC",
            EM_CSR_KALIMBA: "CSR Kalimba",
            EM_Z80: "Zilog Z80",
            EM_VISIUM: "Controls and Data Services VISIUMcore",
            EM_FT32: "FTDI Chip FT32",
            EM_MOXIE: "Moxie processor",
            EM_AMDGPU: "AMD GPU",
            EM_RISCV: "RISC-V",
            EM_BPF: "Linux BPF -- in-kernel virtual machine"
        }.get(int.from_bytes(self.e_machine, 'little'), 'Other')

    def get_version(self) -> str:
        EV_NONE = 0
        EV_CURRENT = 1
        EV_NUM = 2
        return {
            EV_NONE: '0 (Invalid ELF version)',
            EV_CURRENT: '1 (Current)',
            EV_NUM: '2'
        }.get(int.from_bytes(self.e_version, 'little'), 'Other')

    def get_data_encoding(self) -> str:
        ELFDATANONE = 0
        ELFDATA2LSB = 1
        ELFDATA2MSB = 2

        return {
            ELFDATANONE: 'Invalid data encoding',
            ELFDATA2LSB: '2\'s complement, little endian',
            ELFDATA2MSB: '2\'s complement, big endian'
        }.get(self.e_ident[5], 'Other')

    def get_ABI(self) -> str:
        ELFOSABI_SYSV = 0
        ELFOSABI_HPUX = 1
        ELFOSABI_NETBSD = 2
        ELFOSABI_GNU = 3
        ELFOSABI_LINUX = ELFOSABI_GNU
        ELFOSABI_SOLARIS = 6
        ELFOSABI_AIX = 7
        ELFOSABI_IRIX = 8
        ELFOSABI_FREEBSD = 9
        ELFOSABI_TRU64 = 10
        ELFOSABI_MODESTO = 11
        ELFOSABI_OPENBSD = 12
        ELFOSABI_ARM_AEABI = 64
        ELFOSABI_ARM = 97
        ELFOSABI_STANDALONE = 255

        return {
            ELFOSABI_SYSV: "UNIX System V ABI",
            ELFOSABI_HPUX: "HP-UX",
            ELFOSABI_NETBSD: "NetBSD",
            ELFOSABI_GNU: "Object uses GNU ELF extensions",
            ELFOSABI_LINUX: "Object uses GNU ELF extensions",
            ELFOSABI_SOLARIS: "Sun Solaris",
            ELFOSABI_AIX: "IBM AIX",
            ELFOSABI_IRIX: "SGI Irix",
            ELFOSABI_FREEBSD: "FreeBSD",
            ELFOSABI_TRU64: "Compaq TRU64 UNIX",
            ELFOSABI_MODESTO: "Novell Modesto",
            ELFOSABI_OPENBSD: "OpenBSD",
            ELFOSABI_ARM_AEABI: "ARM EABI",
            ELFOSABI_ARM: "ARM",
            ELFOSABI_STANDALONE: "Standalone (embedded) application"
        }.get(self.e_ident[7], 'Other')

    def get_ABI_version(self) -> int:
        return self.e_ident[8]

    def get_entry_point(self) -> int:
        return int.from_bytes(self.e_entry, 'little')

    def get_flags(self) -> int:
        return int.from_bytes(self.e_flags, 'little')

    def get_size(self) -> int:
        return int.from_bytes(self.e_ehsize, 'little')

    def get_phoff(self) -> int:
        return int.from_bytes(self.e_phoff, 'little')

    def get_phnum(self) -> int:
        return int.from_bytes(self.e_phnum, 'little')

    def get_phentsize(self) -> int:
        return int.from_bytes(self.e_phentsize, 'little')

    def get_shoff(self) -> int:
        return int.from_bytes(self.e_shoff, 'little')

    def get_shnum(self) -> int:
        return int.from_bytes(self.e_shnum, 'little')

    def get_shentsize(self) -> int:
        return int.from_bytes(self.e_shentsize, 'little')

    def get_shstrndx(self) -> int:
        return int.from_bytes(self.e_shstrndx, 'little')

    def __str__(self):
        s  = 'ELF Header\n'
        s += '---\n'
        s += 'Magic:   ' + util.tohex(self.e_ident) + '\n'
        s += 'Class:                             ' + self.get_class() + '\n'
        s += 'Data:                              ' + self.get_data_encoding() + '\n'
        s += 'Version:                           ' + self.get_version() + '\n'
        s += 'OS/ABI:                            ' + self.get_ABI() + '\n'
        s += 'ABI Version:                       ' + str(self.get_ABI_version()) + '\n'
        s += 'Type:                              ' + self.get_type() + '\n'
        s += 'Machine:                           ' + self.get_machine() + '\n'
        s += 'Entry point adress:                ' + '0x{:x}'.format(self.get_entry_point()) + '\n'
        s += 'Start of program headers:          ' + str(self.get_phoff()) + ' (bytes into file)\n'
        s += 'Start of section headers:          ' + str(self.get_shoff()) + ' (bytes into file)\n'
        s += 'Flags:                             ' + '0x{:x}'.format(self.get_flags()) + '\n'
        s += 'Size of this header:               ' + str(self.get_size()) + ' (bytes)\n'
        s += 'Size of program headers:           ' + str(self.get_phentsize()) + ' (bytes)\n'
        s += 'Number of program headers:         ' + str(self.get_phnum()) + '\n'
        s += 'Size of section headers:           ' + str(self.get_shentsize()) + ' (bytes)\n'
        s += 'Number of section headers:         ' + str(self.get_shnum()) + '\n'
        s += 'Section header string table index: ' + str(self.get_shstrndx()) + '\n'
        s += '---\n'
        return s


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
        if elfclass not in ('ELF32', 'ELF64'):
            raise ValueError('invalid ELF class')

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
        s += 'Offset:   ' + '0x%0*x' % (padding, self.get_offset()) + '\n'
        s += 'VirtAddr: ' + '0x%0*x' % (padding, self.get_vaddr()) + '\n'
        s += 'PhysAddr: ' + '0x%0*x' % (padding, self.get_paddr()) + '\n'
        s += 'FileSiz:  ' + str(self.get_filesz()) + ' (bytes)\n'
        s += 'MemSiz:   ' + str(self.get_memsz()) + ' (bytes)\n'
        s += 'Flags:    ' + self.get_flags() + '\n'
        s += 'Align:    ' + str(self.get_align()) + '\n'
        return s


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
    def __init__(self, elfclass: str):
        if elfclass not in ('ELF32', 'ELF64'):
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

    def parse(self, mm: 'mmap.mmap', offset: int):
        mm.seek(offset)

        self.sh_name = mm.read(4)
        self.sh_type = mm.read(4)
        if self._class == 'ELF32':
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

    def __str__(self):
        pass
