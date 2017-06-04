from ELF import ELF
import mmap
import os
import sys


class ELFviewer:

    def __init__(self, filename: str):
        if not os.path.exists(filename):
            print('ERROR: file ' + filename + ' does not exist')
            sys.exit(-1)

        if not os.access(filename, os.R_OK):
            print('ERROR: file ' + filename + ' is not readable')
            sys.exit(-1)

        self._filename = filename

    def run(self):
        with ELF(self._filename) as elf:
            print(elf.header)
            for segment in elf.segments:
                print(segment)
            for section in elf.sections:
                print(section)

            #for comp in elf.get_components_by_offset():
            #    print(comp)


USAGE = 'python3 elfviewer <filename>'

if len(sys.argv) != 2:
    print(USAGE)
    sys.exit(-1)

viewer = ELFviewer(sys.argv[1])
viewer.run()