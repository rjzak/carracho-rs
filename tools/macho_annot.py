# Annotate llvm-objdump PPC output of a 32-bit big-endian Mach-O: resolve stub calls and PIC string refs.
import sys, struct, re
binp, disp = sys.argv[1], sys.argv[2]
b = open(binp,'rb').read()
ncmds = struct.unpack('>I', b[16:20])[0]
off = 28; sects = []; symtab = dysym = None
for _ in range(ncmds):
    cmd, size = struct.unpack('>II', b[off:off+8])
    if cmd == 1:
        nsects = struct.unpack('>I', b[off+48:off+52])[0]
        for i in range(nsects):
            s = b[off+56+68*i: off+56+68*(i+1)]
            name = s[:16].rstrip(b'\0').decode(); seg = s[16:32].rstrip(b'\0').decode()
            addr, sz, foff, al, reloff, nrel, flags, r1, r2 = struct.unpack('>9I', s[32:68])
            sects.append((name, seg, addr, sz, foff, flags, r1, r2))
    elif cmd == 2: symtab = struct.unpack('>4I', b[off+8:off+24])
    elif cmd == 0xb: dysym = struct.unpack('>18I', b[off+8:off+80])
    off += size
symoff, nsyms, stroff, strsize = symtab
def symname(i):
    n_strx = struct.unpack('>I', b[symoff+12*i:symoff+12*i+4])[0]
    e = b.index(b'\0', stroff+n_strx); return b[stroff+n_strx:e].decode('latin1')
indoff, nind = dysym[12], dysym[13]
stubs = {}
for (name, seg, addr, sz, foff, flags, r1, r2) in sects:
    if (flags & 0xff) in (8,) and r2:  # S_SYMBOL_STUBS
        for k in range(sz // r2):
            idx = struct.unpack('>I', b[indoff+4*(r1+k): indoff+4*(r1+k)+4])[0]
            stubs[addr + k*r2] = symname(idx) if idx < nsyms else '?'
def v2f(a):
    for (name, seg, addr, sz, foff, flags, r1, r2) in sects:
        if addr <= a < addr+sz and foff: return foff + a - addr
def cstr(a):
    f = v2f(a)
    if f is None: return None
    e = b.find(b'\0', f, f+300)
    s = b[f:e]
    if e > f and all(32 <= c < 127 or c in (9,10,13) for c in s): return s.decode()
    return None
base = None; regs = {}
for line in open(disp):
    line = line.rstrip('\n')
    m = re.match(r'\s+([0-9a-f]+):\s+(\S+)\s*(.*)', line)
    if not m: print(line); base=None; regs={}; continue
    pc = int(m.group(1),16); op = m.group(2); args = m.group(3)
    note = ''
    if op == 'bcl': base = pc + 4
    mm = re.match(r'(\d+), (\d+), (-?\d+)', args)
    if op == 'addis' and mm and base is not None and mm.group(2) == '31':
        regs[mm.group(1)] = base + (int(mm.group(3)) << 16)
    elif op == 'addis' and mm: regs.pop(mm.group(1), None)
    if op in ('addi','lwz') and base is not None:
        mm2 = re.match(r'(\d+), (-?\d+)\((\d+)\)', args) if op=='lwz' else mm
        if op == 'addi' and mm and mm.group(2) in regs:
            a = regs[mm.group(2)] + int(mm.group(3)); s = cstr(a)
            note = f'  ; ={a:#x}' + (f' "{s}"' if s else '')
            regs[mm.group(1)] = a
        elif op == 'lwz' and mm2 and mm2.group(3) in regs:
            a = regs[mm2.group(3)] + int(mm2.group(2)); note = f'  ; [{a:#x}]'
    if op == 'bl':
        t = re.search(r'0x([0-9a-f]+)', args)
        if t and int(t.group(1),16) in stubs: args = f'{stubs[int(t.group(1),16)]}'
    print(f'{pc:6x}: {op:8s}{args}{note}')
