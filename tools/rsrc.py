"""Dump resources from a raw resource fork. Usage: rsrc.py <file.rsrc> [TYPE [ID]]"""
import sys, struct, macresources
res = list(macresources.parse_file(open(sys.argv[1], 'rb').read()))
want_t = sys.argv[2].encode('mac_roman') if len(sys.argv) > 2 else None
want_id = int(sys.argv[3]) if len(sys.argv) > 3 else None
for r in res:
    if want_t is None:
        print(r.type.decode('mac_roman'), r.id, r.name, len(r)); continue
    if r.type != want_t or (want_id is not None and r.id != want_id): continue
    d = bytes(r)
    print('== %s %d %r (%d bytes)' % (r.type.decode('mac_roman'), r.id, r.name, len(d)))
    if r.type == b'STR#':
        n = struct.unpack('>H', d[:2])[0]; p = 2
        for k in range(n):
            l = d[p]; print('  %2d: %s' % (k + 1, d[p+1:p+1+l].decode('mac_roman'))); p += 1 + l
    elif r.type in (b'STR ', b'TEXT'):
        print(d.decode('mac_roman', 'replace').replace('\r', '\n'))
    else:
        print(d[:256].hex(' '))
