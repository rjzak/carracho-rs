import sys, struct, macresources
def adc(src, outlen):
    out = bytearray(); i = 0
    while i < len(src) and len(out) < outlen:
        b = src[i]
        if b & 0x80:
            n = (b & 0x7f) + 1; out += src[i+1:i+1+n]; i += 1 + n
        elif b & 0x40:
            n = (b & 0x3f) + 4; off = struct.unpack('>H', src[i+1:i+3])[0]; i += 3
            for _ in range(n): out.append(out[-off-1])
        else:
            n = ((b >> 2) & 0xf) + 3; off = ((b & 3) << 8) | src[i+1]; i += 2
            for _ in range(n): out.append(out[-off-1])
    return bytes(out)
def ndif_to_raw(data, rsrc):
    bcem = next(r for r in macresources.parse_file(rsrc) if r.type == b'bcem')
    b = bytes(bcem)
    nblocks = struct.unpack('>I', b[66:70])[0]
    cnt = struct.unpack('>I', b[124:128])[0]
    ents = [struct.unpack('>IIII'[0:0] or '>III', b[128+12*k:140+12*k]) for k in range(cnt)]
    img = bytearray(nblocks * 512)
    for k, (st, off, ln) in enumerate(ents):
        sec, typ = st >> 8, st & 0xff
        if typ == 0xff: break
        nxt = ents[k+1][0] >> 8
        size = (nxt - sec) * 512
        if typ == 0x83: chunk = adc(data[off:off+ln], size)
        elif typ == 0x02: chunk = data[off:off+ln]
        elif typ == 0x00: chunk = bytes(size)
        else: raise ValueError(hex(typ))
        img[sec*512:sec*512+len(chunk)] = chunk[:size]
    return bytes(img)
