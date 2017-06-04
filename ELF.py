from ElfHdr import ElfHdr
from ElfSegmentTable import ElfSegmentTable, ElfSegment
from ElfSectionTable import ElfSectionTable, ElfSection
import mmap
from typing import List

class ELF:

    def __init__(self, filename: str):
        self._f = open(filename, 'rb')
        self._mm = mmap.mmap(self._f.fileno(), 0, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ)

        self._ehdr = ElfHdr()
        self._ehdr.parse(self._mm)

        # segments only play a part for the process image,
        # in
        self._segtab = ElfSegmentTable(self._ehdr)
        self._segtab.parse(self._mm)
        self._sectab = ElfSectionTable(self._ehdr)
        self._sectab.parse(self._mm)

        # The section table and the sections are independent
        # components of the ELF file, so it's not really advantageous
        # to consider the sections a part of the section table
        self._sections = self.parse_sections(self._mm)
        self._segments = self.parse_segments(self._mm)

    def parse_segments(self, mm: 'mmap.mmap') -> List['ElfSegment']:
        segments = []
        end = self._segtab.offset + self._segtab.num * self._segtab._entsize
        for offset in range(self._segtab.offset, end, self._segtab.entsize):
            segment = ElfSegment(self._ehdr.get_class())
            segment.parse(mm, offset)
            if segment.get_type() != 'NULL':
                segments.append(segment)
        segments.sort(key=lambda segment: segment.offset)
        return segments

    def parse_sections(self, mm: 'mmap.mmap') -> List['ElfSection']:
        names = self.get_names_section_hdr(mm).content

        sections = []
        end = self._sectab.offset + self._sectab.num * self._sectab.entsize
        for offset in range(self._sectab.offset, end, self._sectab.entsize):
            section = ElfSection(self._ehdr.get_class())
            section.parse(mm, offset, names)
            if section.type != 'NULL':
                sections.append(section)

        sections.sort(key=lambda section: section.offset)
        return sections

    def get_names_section_hdr(self, mm: 'mmap.mmap') -> 'ElfSection':
        section = ElfSection(self._ehdr.get_class())
        offset = self._sectab.offset + self._sectab.strndx * self._sectab.entsize
        section.parse(mm, offset)
        return section

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._mm.close()
        self._f.close()

    def get_components_by_offset(self):
        components = []
        components.append(self.header)
        components.append(self.segment_table)
        components.append(self.section_table)
        for section in self.sections:
            components.append(section)
        components.sort(key=lambda component: component.offset)
        return components

    @property
    def segment_table(self):
        return self._segtab

    @property
    def section_table(self):
        return self._sectab

    @property
    def header(self):
        return self._ehdr

    @property
    def segments(self):
        return self._segments

    @property
    def sections(self):
        return self._sections
