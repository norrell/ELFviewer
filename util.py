import re
from string import printable, whitespace

def hexdump(v: 'bytes', offset: int = 0) -> str:
    # if offset provided use it, otherwise start from 0
    # offset: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f   |   ................
    # offset: 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f   |   ................
    # offset: 20 21 22 23 24 25 26                              |   ........
    # 16 bytes per line
    BYTES_PER_LINE = 16
    OFFSET_BYTES_SEPARATOR = ':  '
    BYTES_DECODED_SEPARATOR = '  |  '

    dump = ''
    chunk_start = 0
    while True:
        chunk_end = chunk_start + BYTES_PER_LINE
        chunk = v[chunk_start:min(chunk_end, len(v))]  # do not overflow v!
        if not chunk:
            break

        off = '0x{off:0{off_pad}x}'.format(off=offset+chunk_start, off_pad=8)
        hex = '{hex:<{hex_pad}s}'.format(hex=tohex(chunk), hex_pad=47)
        chars = '{chars:<{chars_pad}s}'.format(chars=decode(chunk), chars_pad=16)
        dump += off + OFFSET_BYTES_SEPARATOR + hex + BYTES_DECODED_SEPARATOR + chars + '\n'

        chunk_start += BYTES_PER_LINE

    return dump

def decode(v: bytes) -> str:
    s = ''
    for byte in v:
        ch = chr(byte)
        s += ch if ch in printable and ch not in whitespace else '.'
    return s

def tohex(v: bytes) -> str:
    return ' '.join('{:02x}'.format(x) for x in v)

def constants(filename):
    f = open(filename, 'r')

    for line in f:
        line = line.replace('#define ', '').replace('\n', '')
        ndx = line.find('/*')
        line = line[:ndx-1]
        line = ' = '.join(line.split())
        #re.sub(r'(\\t)\1{1,}', ' = ', line)
        print(line)

    f.close()

def mapping(filename):
    f = open(filename, 'r')

    for line in f:
        if line.isspace():
            continue
        line = line.replace('#define ', '').replace('\n', '')
        line = line.replace('\t/* ', ', "').replace(' */', '",')
        line = ': '.join(line.split(maxsplit=1))
        low = line.find(':')
        high = line.find(',')
        if low and high:
            line = line[:low+1] + line[high+1:]
        if len(line) > 0 and line[0] == ',':
            continue
        print(line)

    f.close()

#constants('/home/shosh/tests/elfosabi.txt')
#mapping('/home/shosh/tests/elfosabi.txt')
#constants('/home/shosh/tests/ptype.txt')
#mapping('/home/shosh/tests/ptype.txt')