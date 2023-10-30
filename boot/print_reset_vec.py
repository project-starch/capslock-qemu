import os, sys

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as fin:
        # no compressed instructions
        insn_list = []
        insn = fin.read(4)
        while insn:
            insn_list.append(insn)
            insn = fin.read(4)
    print('uint32_t reset_vec[%d] = {' % len(insn_list))
    for insn in insn_list:
        print('    0x%08x,' % int.from_bytes(insn, byteorder='little'))
    print('};')