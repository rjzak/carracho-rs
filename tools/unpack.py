import sys, struct, os, machfs
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ndif import ndif_to_raw
src, out = sys.argv[1], sys.argv[2]
d = open(src,'rb').read()
dlen, rlen = struct.unpack('>II', d[83:91])
data = d[128:128+dlen]; roff = 128 + ((dlen+127)//128)*128; rsrc = d[roff:roff+rlen]
raw = ndif_to_raw(data, rsrc)
open(out + '.hfs', 'wb').write(raw)
vol = machfs.Volume(); vol.read(raw)
os.makedirs(out, exist_ok=True)
def walk(folder, path):
    for k, v in folder.items():
        p = os.path.join(path, k.replace('/', ':'))
        if isinstance(v, machfs.Folder):
            os.makedirs(p, exist_ok=True); walk(v, p)
        else:
            open(p,'wb').write(v.data)
            if v.rsrc: open(p+'.rsrc','wb').write(v.rsrc)
            print(f'{p[len(out):]:60s} {v.type} {v.creator} data={len(v.data)} rsrc={len(v.rsrc)}')
walk(vol, out)
