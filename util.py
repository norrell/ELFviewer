import re

def tohex(v):
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
mapping('/home/shosh/tests/ptype.txt')