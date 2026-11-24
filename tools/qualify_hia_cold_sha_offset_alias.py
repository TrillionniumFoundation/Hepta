from pathlib import Path
from hashlib import sha256
import ctypes, json, random, struct, sys, time
from collections import Counter
from hepta.hia_sha256_stream_native import NativeSha256Stream
D=Path(sys.argv[1]); images={k:NativeSha256Stream((D/(k+'.flat')).read_bytes(),sha256((D/(k+'.flat')).read_bytes()).hexdigest()) for k in ('old','new')}
GUARD=b'\x93\xa8\x52\x61'*4
rng=random.Random(0x64A11A5); counts=Counter(); rows=[]; start=time.monotonic_ns()
init_in=ctypes.create_string_buffer(b'\x00'); init_o=ctypes.create_string_buffer(32); init_w=ctypes.create_string_buffer(1184)
assert images['old']._entry(init_in,1,init_o,32,init_w,1184)==0
state=init_w.raw
# Memory accesses occur in the same original order even for foreign aliases;
# these are ABI stress observations, not affine-language admission claims.
displacements=list(range(1104,1121))+[0,1,7,8,63,64,512,1024,1088,1096,1104,1112,1168,1175,1176,-64,-1,64,2048]
for trial in range(2000):
    owner=bytearray(rng.randbytes(8192)); wo=2048; wn=1184+(trial%18)
    so=wo+displacements[trial%len(displacements)]
    size=[0,1,7,8,55,56,63,64,65,127,128,129,255,256,511,512,1024,2048][trial%18]
    used=[0,1,7,8,31,55,56,57,63][trial%9]
    oo=[wo,wo+16,wo+1104,wo+1112,wo+1168,0,7000][trial%7]; on=41
    owner[wo:wo+1184]=state
    total=64*rng.randrange(1,10000)+used
    struct.pack_into('<QQQ',owner,wo+1088,total,used,1)
    struct.pack_into('<Q',owner,wo+1176,0x3153484132353648)
    op=2 if trial%11==0 else 1
    if op==2:size=0
    owner[so]=op
    sn=size+1
    observed=[]
    for key, image in images.items():
        buf=ctypes.create_string_buffer(GUARD+owner+GUARD,len(owner)+32)
        result=image._entry(ctypes.byref(buf,16+so),sn,ctypes.byref(buf,16+oo),on,ctypes.byref(buf,16+wo),wn)
        assert buf.raw[:16]==GUARD and buf.raw[-16:]==GUARD,('canary',trial,key)
        observed.append((result,buf.raw[16:-16]))
    assert observed[0]==observed[1],('alias mismatch',trial,so-wo,size,used,oo-wo,observed[0][0],observed[1][0])
    counts[str(observed[0][0])]+=1
    rows.append({'case':trial,'source_offset':so,'source_bytes':sn,'output_offset':oo,'output_bytes':on,'state_offset':wo,'state_bytes':wn,'used':used,'result':observed[0][0],'owner_before_sha256':sha256(owner).hexdigest(),'owner_after_sha256':sha256(observed[0][1]).hexdigest(),'complete_owner_byte_equal':True,'canaries_unchanged':True})
report={'schema':'hepta.hia.cold-sha-displaced-alias.v1','passed':True,'cases':len(rows),'results':dict(counts),'elapsed_ns':time.monotonic_ns()-start,'images':{k:sha256((D/(k+'.flat')).read_bytes()).hexdigest() for k in images},'scope':'foreign pointer offset stress; no added affine-language alias admission'}
(D/'offset-alias-cases.jsonl').write_text(''.join(json.dumps(r,separators=(',',':'))+'\n' for r in rows))
(D/'offset-alias.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report),flush=True)
