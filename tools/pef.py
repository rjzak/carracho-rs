"""PEF (Preferred Executable Format) loader and annotated PowerPC disassembler.

Usage: python -I pef.py <pef-file> [--funcs] [--func NAME_SUBSTR ...] [--all]

Loads code/data sections, unpacks pattern-initialized data, applies loader
relocations, recovers CodeWarrior traceback-table function names, and prints
disassembly with TOC references resolved to imports, strings and functions.
"""
import struct, sys, re
import capstone

CODE_BASE = 0x00000000
SECT_STRIDE = 0x10000000  # section i is loaded at i * SECT_STRIDE


def read_arg(buf, i):
    v = 0
    while True:
        b = buf[i]; i += 1
        v = (v << 7) | (b & 0x7f)
        if not b & 0x80:
            return v, i


def unpack_pidata(buf, total):
    out = bytearray(); i = 0
    while i < len(buf):
        b = buf[i]; i += 1
        op, cnt = b >> 5, b & 0x1f
        if cnt == 0:
            cnt, i = read_arg(buf, i)
        if op == 0:
            out += bytes(cnt)
        elif op == 1:
            out += buf[i:i+cnt]; i += cnt
        elif op == 2:
            rep, i = read_arg(buf, i)
            blk = buf[i:i+cnt]; i += cnt
            out += blk * (rep + 1)
        elif op == 3:
            custom, i = read_arg(buf, i); rep, i = read_arg(buf, i)
            common = buf[i:i+cnt]; i += cnt
            for _ in range(rep):
                out += common + buf[i:i+custom]; i += custom
            out += common
        elif op == 4:
            custom, i = read_arg(buf, i); rep, i = read_arg(buf, i)
            for _ in range(rep):
                out += bytes(cnt) + buf[i:i+custom]; i += custom
            out += bytes(cnt)
        else:
            raise ValueError('bad pidata opcode %d' % op)
    out += bytes(max(0, total - len(out)))
    return bytes(out)


class PEF:
    def __init__(self, path):
        self.raw = raw = open(path, 'rb').read()
        assert raw[:8] == b'Joy!peff', 'not a PEF container'
        nsect = struct.unpack('>H', raw[32:34])[0]
        self.sections = []
        for k in range(nsect):
            h = raw[40+28*k: 68+28*k]
            nameoff, defaddr, total, unpacked, clen, coff = struct.unpack('>iIIIII', h[:24])
            kind = h[24]
            body = raw[coff:coff+clen]
            if kind == 2:
                body = unpack_pidata(body, total)
            elif kind in (0, 1, 3, 6):
                body = body + bytes(max(0, total - len(body)))
            self.sections.append(dict(kind=kind, base=k*SECT_STRIDE, data=bytearray(body), total=total))
        self.imports = []
        self.reloc_targets = {}  # absolute address -> ('import', name) | ('sect', idx)
        self.load_loader()
        self.code_idx = next(i for i, s in enumerate(self.sections) if s['kind'] == 0)
        self.data_idx = next(i for i, s in enumerate(self.sections) if s['kind'] in (1, 2))
        self.find_toc()
        self.find_functions()

    def load_loader(self):
        ls = next(s for s in self.sections if s['kind'] == 4)
        L = bytes(ls['data'])
        (self.main_sect, self.main_off, _, _, _, _, nlib, nsym, nrelsec, relinstr,
         stroff, _, _, _) = struct.unpack('>iIiIiIIIIIIIII', L[:56])
        def lstr(o):
            e = L.index(b'\0', stroff + o); return L[stroff+o:e].decode('mac_roman')
        p = 56
        self.libs = []
        for _ in range(nlib):
            no, _, _, cnt, first, opt, _, _ = struct.unpack('>IIIIIBBH', L[p:p+24]); p += 24
            self.libs.append((lstr(no), first, cnt))
        for k in range(nsym):
            w = struct.unpack('>I', L[p:p+4])[0]; p += 4
            lib = next((n for n, f, c in self.libs if f <= k < f + c), '?')
            self.imports.append((lstr(w & 0xffffff), lib))
        for r in range(nrelsec):
            sidx, _, cnt, first = struct.unpack('>HHII', L[p:p+12]); p += 12
            words = struct.unpack('>%dH' % cnt, L[relinstr+first: relinstr+first+2*cnt])
            self.relocate(sidx, words)

    def relocate(self, sidx, words):
        sect = self.sections[sidx]; d = sect['data']
        state = dict(addr=0, imp=0, C=0, D=1)
        def add(off, target):
            v = struct.unpack('>I', d[off:off+4])[0]
            if target[0] == 'sect':
                v = (v + self.sections[target[1]]['base']) & 0xffffffff
                struct.pack_into('>I', d, off, v)
            self.reloc_targets[sect['base'] + off] = target
        def run(instrs):
            i = 0
            while i < len(instrs):
                w = instrs[i]; i += 1
                a = state['addr']
                if w >> 14 == 0:
                    skip, n = (w >> 6) & 0xff, w & 0x3f
                    a += 4 * skip
                    for _ in range(n): add(a, ('sect', state['D'])); a += 4
                elif w >> 13 == 2:
                    sub, n = (w >> 9) & 0xf, (w & 0x1ff) + 1
                    for _ in range(n):
                        if sub == 0: add(a, ('sect', state['C'])); a += 4
                        elif sub == 1: add(a, ('sect', state['D'])); a += 4
                        elif sub == 2: add(a, ('sect', state['C'])); add(a+4, ('sect', state['D'])); a += 12
                        elif sub == 3: add(a, ('sect', state['C'])); add(a+4, ('sect', state['D'])); a += 8
                        elif sub == 4: add(a, ('sect', state['D'])); a += 8
                        elif sub == 5: add(a, ('import', state['imp'])); state['imp'] += 1; a += 4
                        else: raise ValueError('reloc run sub %d' % sub)
                elif w >> 13 == 3:
                    sub, idx = (w >> 9) & 0xf, w & 0x1ff
                    if sub == 0: add(a, ('import', idx)); state['imp'] = idx + 1; a += 4
                    elif sub == 1: state['C'] = idx
                    elif sub == 2: state['D'] = idx
                    elif sub == 3: add(a, ('sect', idx)); a += 4
                    else: raise ValueError('reloc sm sub %d' % sub)
                elif w >> 12 == 8:
                    a += (w & 0xfff) + 1
                elif w >> 12 == 9:
                    blk, rep = ((w >> 8) & 0xf) + 1, (w & 0xff) + 1
                    state['addr'] = a
                    prev = instrs[i-1-blk:i-1]
                    for _ in range(rep): run(prev)
                    a = state['addr']
                elif w >> 10 == 0x28:
                    a = ((w & 0x3ff) << 16) | instrs[i]; i += 1
                elif w >> 10 == 0x29:
                    idx = ((w & 0x3ff) << 16) | instrs[i]; i += 1
                    add(a, ('import', idx)); state['imp'] = idx + 1; a += 4
                elif w >> 10 == 0x2c:
                    blk, rep = ((w >> 6) & 0xf) + 1, (((w & 0x3f) << 16) | instrs[i]) + 1; i += 1
                    state['addr'] = a
                    prev = instrs[i-2-blk:i-2]
                    for _ in range(rep): run(prev)
                    a = state['addr']
                elif w >> 10 == 0x2d:
                    sub, idx = (w >> 6) & 0xf, ((w & 0x3f) << 16) | instrs[i]; i += 1
                    if sub == 0: add(a, ('sect', idx)); a += 4
                    elif sub == 1: state['C'] = idx
                    elif sub == 2: state['D'] = idx
                else:
                    raise ValueError('bad reloc opcode %04x' % w)
                state['addr'] = a
        # Repeat opcodes re-run earlier instructions; keep the full list available.
        run(list(words))

    # --- memory helpers -------------------------------------------------
    def sect_of(self, addr):
        i = addr // SECT_STRIDE
        if 0 <= i < len(self.sections) and addr - self.sections[i]['base'] < len(self.sections[i]['data']):
            return self.sections[i]
        return None

    def u32(self, addr):
        s = self.sect_of(addr)
        if not s: return None
        o = addr - s['base']; return struct.unpack('>I', s['data'][o:o+4])[0]

    def cstr(self, addr, pascal=False):
        s = self.sect_of(addr)
        if not s: return None
        o = addr - s['base']; d = s['data']
        if pascal:
            n = d[o]; t = bytes(d[o+1:o+1+n])
        else:
            e = d.find(b'\0', o, o + 400)
            if e < 0: return None
            t = bytes(d[o:e])
        if len(t) >= 2 and all(32 <= c < 127 or c in (9, 10, 13) or c >= 0x80 for c in t):
            return t.decode('mac_roman')
        return None

    def target_name(self, addr):
        """Describe what a pointer-sized value at `addr` (a TOC slot) refers to."""
        t = self.reloc_targets.get(addr)
        v = self.u32(addr)
        if t and t[0] == 'import':
            return 'import:' + self.imports[t[1]][0]
        if v is None: return None
        return self.describe(v)

    def describe(self, v):
        if v in self.func_by_addr: return 'func:' + self.func_by_addr[v]
        s = self.sect_of(v)
        if not s: return None
        # transition vector pointing at code?
        if s['kind'] in (1, 2):
            t = self.reloc_targets.get(v)
            if t and t[0] == 'import': return 'tvec->import:' + self.imports[t[1]][0]
            w = self.u32(v)
            if w in self.func_by_addr and self.reloc_targets.get(v) == ('sect', self.code_idx):
                return 'tvec:' + self.func_by_addr[w]
        st = self.cstr(v)
        if st: return 'str:%r' % st
        return 'data:%#x' % v

    def find_toc(self):
        tv = self.sections[self.main_sect]['base'] + self.main_off
        self.toc = self.u32(tv + 4)

    def find_functions(self):
        code = self.sections[self.code_idx]['data']; base = self.sections[self.code_idx]['base']
        self.funcs = []  # (start, end_marker, name)
        i = 0
        while i < len(code) - 12:
            if code[i:i+4] == b'\0\0\0\0' and i >= 4 and code[i-4:i] != b'\0\0\0\0' and i + 64 < len(code):
                f1, f2, fixed, flt = code[i+6], code[i+7], code[i+10], code[i+11]
                if code[i+4] == 0 and f2 & 0x40 and f1 & 0x20:
                    p = i + 12
                    if fixed or (flt >> 1): p += 4
                    tboff = struct.unpack('>I', code[p:p+4])[0]; p += 4
                    if f2 & 0x80: p += 4
                    if f1 & 0x08:
                        n = struct.unpack('>I', code[p:p+4])[0]; p += 4 + 4*n
                    if p + 2 > len(code):
                        i += 4; continue
                    nl = struct.unpack('>H', code[p:p+2])[0]
                    name = code[p+2:p+2+nl].decode('latin1')
                    if 0 < nl < 400 and tboff <= i:
                        self.funcs.append((base + i - tboff, base + i, demangle_cw(name.lstrip('.'))))
                        i = (p + 2 + nl + 3) & ~3
                        continue
            i += 4
        self.func_by_addr = {a: n for a, e, n in self.funcs}
        # CodeWarrior cross-TOC glue stubs: lwz r12,X(r2); stw r2,20(r1); lwz r0,0(r12); lwz r2,4(r12); mtctr r0; bctr
        # __ptr_glue: lwz r0,0(r12); stw r2,20(r1); mtctr r0; lwz r2,4(r12); bctr
        self.ptr_glue = None
        for j in range(0, len(code) - 20, 4):
            if struct.unpack('>5I', code[j:j+20]) == (0x800c0000, 0x90410014, 0x7c0903a6, 0x804c0004, 0x4e800420):
                self.ptr_glue = base + j; break
        self.glue = {}
        for j in range(0, len(code) - 24, 4):
            w = struct.unpack('>6I', code[j:j+24])
            if w[0] >> 16 == 0x8182 and w[1:] == (0x90410014, 0x800c0000, 0x804c0004, 0x7c0903a6, 0x4e800420):
                off = w[0] & 0xffff
                if off & 0x8000: off -= 0x10000
                self.glue[base + j] = self.target_name(self.toc + off) or ('toc[%d]' % off)


def demangle_cw(n):
    """Light CodeWarrior demangling: Method__7ClassNameF... -> ClassName::Method(...)."""
    m = re.match(r'^(.*?)__(\d+)(\w+)$', n)
    if m:
        meth, ln, rest = m.group(1), int(m.group(2)), m.group(3)
        cls, sig = rest[:ln], rest[ln:]
        if meth == '__ct': meth = cls
        elif meth == '__dt': meth = '~' + cls
        return '%s::%s  [%s]' % (cls, meth, sig)
    return n


def disasm(pef, start, end, out):
    code = pef.sections[pef.code_idx]['data']; base = pef.sections[pef.code_idx]['base']
    md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
    md.detail = False
    regs = {}
    last_vt = None
    for ins in md.disasm(bytes(code[start-base:end-base]), start):
        note = ''
        ops = ins.op_str.replace('r', '') if False else ins.op_str
        mn = ins.mnemonic
        m = re.match(r'r(\d+), (-?(?:0x)?[0-9a-f]+)\(r(\d+)\)$', ops)
        if mn in ('lwz', 'addi', 'la') or (mn.startswith('l') and m):
            if m:
                rd, off, ra = int(m.group(1)), int(m.group(2), 0), int(m.group(3))
                if ra == 2 and mn == 'lwz':
                    slot = pef.toc + off
                    d = pef.target_name(slot); note = d or ''
                    v = pef.u32(slot)
                    if pef.reloc_targets.get(slot, ('',))[0] == 'sect': regs[rd] = v
                    else: regs.pop(rd, None)
                elif ra in regs and mn == 'lwz':
                    a = regs[ra] + off
                    note = '[%s]' % (pef.describe(a) or '%#x' % a); regs.pop(rd, None)
                elif ra in regs and mn.startswith('l'):
                    note = '[%#x]' % (regs[ra] + off); regs.pop(rd, None)
                elif mn.startswith('l'):
                    regs.pop(rd, None)
            m2 = re.match(r'r(\d+), r(\d+), (-?(?:0x)?[0-9a-f]+)$', ops)
            if mn == 'addi' and m2:
                rd, ra, imm = int(m2.group(1)), int(m2.group(2)), int(m2.group(3), 0)
                if ra == 2:
                    a = pef.toc + imm; regs[rd] = a; note = pef.describe(a) or ''
                elif ra in regs:
                    a = regs[ra] + imm; regs[rd] = a; note = pef.describe(a) or '%#x' % a
                else:
                    regs.pop(rd, None)
        elif mn in ('bl',) and ops.startswith('0x'):
            t = int(ops, 16)
            if t in pef.glue: note = '-> ' + pef.glue[t]
            elif t in pef.func_by_addr: note = '-> ' + pef.func_by_addr[t]
            elif t == pef.ptr_glue:
                note = '-> virtual call vtable+%#x' % last_vt if last_vt is not None else '-> indirect call via r12'
            else: note = '-> sub_%x' % t
        elif mn in ('mr',):
            a, b = ops.replace('r', '').split(', ')
            if int(b) in regs: regs[int(a)] = regs[int(b)]
            else: regs.pop(int(a), None)
        elif mn == 'li':
            regs.pop(int(ops.split(',')[0][1:]), None)
        mv = re.match(r'r12, (0x[0-9a-f]+|\d+)\(r12\)$', ops)
        if mn == 'lwz' and mv: last_vt = int(mv.group(1), 0)
        elif mn == 'bl': last_vt = None
        out.write('%8x:  %-8s %-28s %s\n' % (ins.address, mn, ops, ('; ' + note) if note else ''))


def load_names(pef, path):
    """Apply a names file: one `hexaddr name` per line, `#` comments."""
    for line in open(path, encoding='utf-8'):
        line = line.split('#', 1)[0].strip()
        if line:
            a, n = line.split(None, 1)
            pef.func_by_addr[int(a, 16)] = n


def main():
    pef = PEF(sys.argv[1])
    args = sys.argv[2:]
    if '--names' in args:
        load_names(pef, args[args.index('--names') + 1])
    if '--funcs' in args:
        for a, e, n in pef.funcs: print('%8x %6d  %s' % (a, e - a, n))
        return
    if '--imports' in args:
        for n, l in pef.imports: print(l, n)
        return
    if '--hex' in args:
        a = int(args[args.index('--hex') + 1], 16); n = int(args[args.index('--hex') + 2], 0)
        s = pef.sect_of(a); o = a - s['base']; d = bytes(s['data'][o:o+n])
        for k in range(0, n, 16):
            row = d[k:k+16]
            print('%08x  %-48s %s' % (a + k, row.hex(' '), ''.join(chr(c) if 32 <= c < 127 else '.' for c in row)))
        return
    if '--full' in args:
        # Whole code section, with a header at every named function and every bl target.
        c = pef.sections[pef.code_idx]; base = c['base']; code = c['data']
        md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
        starts = dict(pef.func_by_addr)
        named = {a for a, e, n in pef.funcs}
        for k in range(0, len(code), 4):
            w = struct.unpack('>I', code[k:k+4])[0]
            if w >> 26 == 18 and w & 3 == 1:
                off = w & 0x3fffffc
                if off & 0x2000000: off -= 0x4000000
                t = base + k + off
                if 0 <= t - base < len(code) and t not in starts and t not in pef.glue:
                    starts[t] = 'sub_%x' % t
        bounds = sorted(starts) + [base + len(code)]
        for a, b in zip(bounds, bounds[1:]):
            print('\n==== %s  @%#x' % (starts[a], a))
            disasm(pef, a, b, sys.stdout)
        return
    pats = [a for a in args if not a.startswith('--') and not re.match(r'^(0x)?[0-9a-f]+$', a)]
    for a, e, n in pef.funcs:
        if '--all' in args or any(p in n for p in pats):
            print('\n==== %s  @%#x' % (n, a))
            disasm(pef, a, e, sys.stdout)


if __name__ == '__main__':
    main()
