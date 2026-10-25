"""Run functions from a PEF binary under Unicorn, to produce test vectors from
the original code.

Usage: python -I pefemu.py <pef-file>    (runs the built-in vector generators)

Only self-contained code (no calls into Mac OS imports) can be run.
"""
import struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pef
from unicorn import Uc, UC_ARCH_PPC, UC_MODE_PPC32, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE
from unicorn.ppc_const import UC_PPC_REG_PC, UC_PPC_REG_LR, UC_PPC_REG_1, UC_PPC_REG_2, UC_PPC_REG_3

STACK_TOP = 0x7ff00000
HEAP = 0x60000000
RETURN = 0x7ffff000


class Emu:
    def __init__(self, path):
        self.pef = pef.PEF(path)
        self.uc = Uc(UC_ARCH_PPC, UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN)
        for s in self.pef.sections:
            if s['kind'] in (0, 1, 2, 3, 6):
                size = (len(s['data']) + 0xfff) & ~0xfff
                self.uc.mem_map(s['base'], max(size, 0x1000))
                self.uc.mem_write(s['base'], bytes(s['data']))
        self.uc.mem_map(STACK_TOP - 0x100000, 0x100000)
        self.uc.mem_map(HEAP, 0x1000000)
        self.uc.mem_map(RETURN & ~0xfff, 0x1000)
        self.uc.mem_write(RETURN, struct.pack('>I', 0x48000000))  # b . (never reached)
        self.heap = HEAP
        self.func = {n.split('  ')[0]: a for a, e, n in self.pef.funcs}

    def alloc(self, data=b'', size=None):
        size = size or len(data)
        p = self.heap; self.heap += (size + 15) & ~15
        if data: self.uc.mem_write(p, data)
        return p

    def call(self, addr, *args):
        uc = self.uc
        uc.reg_write(UC_PPC_REG_1, STACK_TOP - 0x1000)
        uc.reg_write(UC_PPC_REG_2, self.pef.toc)
        uc.reg_write(UC_PPC_REG_LR, RETURN)
        for i, a in enumerate(args):
            uc.reg_write(UC_PPC_REG_3 + i, a & 0xffffffff)
        uc.emu_start(addr, RETURN, count=50_000_000)
        return uc.reg_read(UC_PPC_REG_3)

    def read(self, p, n):
        return bytes(self.uc.mem_read(p, n))


def main():
    emu = Emu(sys.argv[1])
    tlci, tlce, tlcd = emu.func['Tlci'], emu.func['Tlce'], emu.func['Tlcd']
    ctx = emu.alloc(size=0x1048)
    for key in (b'YOYO', bytes(range(1, 25))):
        emu.call(tlci, ctx, emu.alloc(key), len(key))
        for block in (bytes(8), b'\x01\x23\x45\x67\x89\xab\xcd\xef'):
            l, r = emu.alloc(block[:4]), emu.alloc(block[4:])
            emu.call(tlce, ctx, l, r)
            enc = emu.read(l, 4) + emu.read(r, 4)
            emu.call(tlcd, ctx, l, r)
            dec = emu.read(l, 4) + emu.read(r, 4)
            assert dec == block
            print('blowfish key=%s pt=%s ct=%s' % (key.hex(), block.hex(), enc.hex()))
    # The login response is MD5 (rendered as lowercase hex by sprintf, which needs the OS).
    for msg in (b'', b'abc', bytes(range(24))):
        md5 = emu.alloc(size=0x58 + 16)
        emu.call(emu.func['MD5Init'], md5)
        emu.call(emu.func['MD5Update'], md5, emu.alloc(msg or b'\0'), len(msg))
        emu.call(emu.func['MD5Final'], md5)
        print('md5 msg=%s -> %s' % (msg.hex(), emu.read(md5 + 0x58, 16).hex()))


if __name__ == '__main__':
    main()
