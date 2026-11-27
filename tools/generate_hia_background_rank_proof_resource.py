"""One installation-owned native resource bundle for Runtime, BG and LLVM.

All admission and custody policy is HIA. The original component-loader profile
is unchanged; this profile captures one fixed public-proof executable. No request selects a file, digest, pointer or native entry.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_native_fixed_component_loader as base
ROOT=Path(__file__).resolve().parents[1]
C=dict(base.C)
C.update(Q=int.from_bytes(b'HIABPRQ1','little'),R=int.from_bytes(b'HIABPRR1','little'),
 TAG=int.from_bytes(b'HIABPRW1','little'),CATQ=int.from_bytes(b'HIABPCQ1','little'),
 CATR=int.from_bytes(b'HIABPCA1','little'),NODETAG=int.from_bytes(b'HIABPRN1','little'),
 WORK=8<<20,INDEX=304,BANK=312,THRESHOLD=344,THRESHOLD_N=352,NONCE=368,RAWFD=384,
 SNAP_BANK=16384,SNAP_THRESHOLD=16416,SNAP_NONCE=16440)
def replace_function(source,name,body):
    pattern=r'^def '+re.escape(name)+r'\([^\n]*\n.*?(?=^def |\Z)'
    source,n=re.subn(pattern,lambda _:body.strip()+'\n\n',source,flags=re.M|re.S)
    assert n==1,(name,n)
    return source
def source_program():
    source=base.SOURCE
    source=source.replace('def loader(', 'def resources(')
    source=replace_function(source,'begin',r'''
def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or word(s,0)!=Q or word(s,8)>4 or length(o)<OUT or length(w)!=WORK:
        return BAD
    op=word(s,8)
    i=16
    while i<128:
        if op!=3 or i<24 or i>40:
            if word(s,i)!=0:
                return BAD
        i=i+8
    clear(o,128,384)
    put(o,OP,op)
    put(o,KNOWN,1)
    return system(o,1,39,0,0,0,0,0,0,0)
''')
    source=source.replace('put(w,56,word(s,16))','put(w,56,1)\n        put(w,INDEX,1)\n        put(w,RAWFD,NONE)\n        i=0\n        while i<1:\n            put(w,BANK+i*8,NONE)\n            i=i+1')
    source=source.replace('put(w,FRAME+8,word(s,16))','put(w,FRAME+8,1)')
    source=source.replace('count==0 or count>128','count!=get(w,INDEX)')
    source=source.replace('put(w,EXPORT_N,count)\n        put(w,EXPORT_AT,CATALOG+128+pn+sn)',
      'if pn+sn!=r-128:\n            return fail(o,w,3,14)')
    source=source.replace('within(w,EXPECTED,CATALOG+64,32)\n        put(o,PH,11)',
      'within(w,EXPECTED,CATALOG+64,32)\n        if get(w,INDEX)>1:\n            return capture(o,w)\n        put(o,PH,11)')
    start='''        n=fd_path(w,FRAME+192,get(w,ORIGINFD))
        store(w,FRAME+192+n,47)'''
    first=source.index(start);last=source.index('    if phase==21:',first)
    capture=source[first:last]
    source=source[:first]+'        return capture(o,w)\n'+source[last:]
    source+='\ndef capture(o:mutbuf,w:mutbuf) -> u32:\n'+''.join(line[4:]+'\n'for line in capture.rstrip().splitlines())+'\n'
    source=replace_function(source,'sealing',r'''
def sealing(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==100:
        if failed(r):
            return fail(o,w,1,r)
        if r<3:
            put(w,RAWFD,r)
            return system(o,115,72,0,r,1030,3,0,0,0)
        put(w,MEMFD,r)
        put(w,WRITE_AT,0)
        return write_image(o,w)
    if phase==115:
        if failed(r) or r<3 or r>2147483647:
            return fail(o,w,1,r)
        put(w,MEMFD,r)
        put(w,WRITE_AT,0)
        return close_fd(o,w,116,RAWFD)
    if phase==116:
        return write_image(o,w)
    if phase==101:
        if r==18446744073709551612:
            return write_image(o,w)
        left=get(w,FILE_N)-get(w,WRITE_AT)
        if failed(r) or r==0 or r>left:
            return fail(o,w,1,r)
        put(w,WRITE_AT,get(w,WRITE_AT)+r)
        return write_image(o,w)
    if phase==102:
        if r!=0:
            return fail(o,w,1,r)
        return system(o,103,72,0,get(w,MEMFD),1034,0,0,0,0)
    if phase==103:
        if r!=15:
            return fail(o,w,2,r)
        return system(o,104,5,4,get(w,MEMFD),STAT,0,0,0,0)
    if phase==104:
        if failed(r) or (get(w,STAT+24)&61440)!=32768 or get(w,STAT+16)!=0 or get(w,STAT+48)!=get(w,FILE_N):
            return fail(o,w,2,r)
        clear(w,SHAWORK,1184)
        put(w,READ_AT,0)
        store(w,HASHINPUT,0)
        return role(o,105,12,HASHINPUT,1,DIGEST,32,SHAWORK,1184)
    if phase==105:
        if r!=0:
            return fail(o,w,2,r)
        return read_sealed(o,w)
    if phase==106:
        if r==18446744073709551612:
            return read_sealed(o,w)
        n=get(w,FILE_N)-get(w,READ_AT)
        if n>1048576:
            n=1048576
        if failed(r) or r==0 or r>n:
            return fail(o,w,1,r)
        put(w,WRITE_AT,r)
        store(w,HASHINPUT,1)
        return role(o,107,12,HASHINPUT,1+r,DIGEST,32,SHAWORK,1184)
    if phase==107:
        if r!=0:
            return fail(o,w,2,r)
        put(w,READ_AT,get(w,READ_AT)+get(w,WRITE_AT))
        return read_sealed(o,w)
    if phase==108:
        if r!=32 or equal(w,DIGEST,EXPECTED,32)==0:
            return fail(o,w,2,r)
        mode=320
        if get(w,INDEX)==4:
            mode=256
        return system(o,109,91,0,get(w,MEMFD),mode,0,0,0,0)
    if phase==109:
        if r!=0:
            return fail(o,w,1,r)
        index=get(w,INDEX)
        if index==4:
            put(w,THRESHOLD_N,get(w,FILE_N))
            return system(o,110,9,0,0,get(w,FILE_N),1,2,get(w,MEMFD),0)
        put(w,BANK+(index-1)*8,get(w,MEMFD))
        put(w,MEMFD,NONE)
        return retire_capture(o,w,111)
    if phase==110:
        if failed(r) or r==0:
            put(w,THRESHOLD_N,0)
            return fail(o,w,1,r)
        put(w,THRESHOLD,r)
        put(w,BANK+24,get(w,MEMFD))
        put(w,MEMFD,NONE)
        return retire_capture(o,w,111)
    if phase==111:
        if stable_retired(o,w,r)==0:
            return finish(o,w,1,get(w,ERRNO))
        clear(w,FSWORK,FSWORK_N)
        clear(w,FSOUT,256)
        if get(w,INDEX)<1:
            put(w,INDEX,get(w,INDEX)+1)
            put(w,56,get(w,INDEX))
            clear(w,FRAME,128)
            put(w,FRAME,CATQ)
            put(w,FRAME+8,get(w,INDEX))
            return role(o,10,10,FRAME,128,CATALOG,65536,SMALL,128)
        return system(o,112,318,1,NONCE,8,0,0,0,0)
    if phase==112:
        if r!=8 or get(w,NONCE)==0:
            return fail(o,w,1,r)
        return close_fd(o,w,114,ORIGINFD)
    if phase==114:
        put(w,32,2)
        return finish(o,w,0,0)
    return BAD
''')
    for name in('next_symbol','symbols','read_maps','read_post_close_maps','mapping_present','maps_space','maps_uint','maps_path'):
        source=replace_function(source,name,'')
    source=source.replace('    if phase<300:\n        return symbols(o,w,phase,r)\n','')
    source=replace_function(source,'retirement',r'''
def retirement(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==701:
        return cleanup(o,w)
    if phase==702:
        if failed(r):
            put(o,PENDING,1)
            return finish(o,w,1,r)
        put(w,PATHMAP,0)
        put(w,PATHCAP,0)
        return cleanup(o,w)
    if phase==703:
        if stable_retired(o,w,r)==0:
            return finish(o,w,1,get(w,ERRNO))
        return cleanup(o,w)
    if phase==704:
        if r!=0:
            put(o,PENDING,1)
            return finish(o,w,1,r)
        put(w,THRESHOLD,0)
        put(w,THRESHOLD_N,0)
        return cleanup(o,w)
    return BAD
''')
    source=replace_function(source,'cleanup',r'''
def cleanup(o:mutbuf,w:mutbuf) -> u32:
    if get(w,UNKNOWN)!=0:
        return quarantine(o,w,get(w,ERRNO))
    if get(w,PENDING_HEAD)!=0:
        return retry_nodes(o,w)
    if get(w,FS_ACTIVE)!=0:
        return retire_capture(o,w,703)
    if get(w,THRESHOLD)!=0:
        return system(o,704,11,0,get(w,THRESHOLD),get(w,THRESHOLD_N),0,0,0,0)
    if get(w,MEMFD)!=NONE:
        return close_fd(o,w,701,MEMFD)
    if get(w,RAWFD)!=NONE:
        return close_fd(o,w,701,RAWFD)
    i=0
    while i<1:
        if get(w,BANK+i*8)!=NONE:
            return close_fd(o,w,701,BANK+i*8)
        i=i+1
    if get(w,SOURCEFD)!=NONE:
        return close_fd(o,w,701,SOURCEFD)
    if get(w,ORIGINFD)!=NONE:
        return close_fd(o,w,701,ORIGINFD)
    if get(w,PATHMAP)!=0:
        return system(o,702,11,0,get(w,PATHMAP),get(w,PATHCAP),0,0,0,0)
    put(w,32,4)
    if get(o,OP)==1:
        put(o,CONSUMED,1)
    put(o,PENDING,0)
    return finish(o,w,get(o,STATUS),get(o,DETAIL))
''')
    source=replace_function(source,'snapshot',r'''
def snapshot(o:mutbuf,w:mutbuf) -> u64:
    put(o,SNAP_STATE,get(w,32))
    put(o,SNAP_COUNT,get(w,COUNT))
    if get(o,DELIVERED)==1:
        i=0
        while i<1:
            put(o,SNAP_BANK+i*8,get(w,BANK+i*8))
            i=i+1
        put(o,SNAP_SOURCEFD,get(w,SOURCEFD))
        put(o,SNAP_THRESHOLD,get(w,THRESHOLD))
        put(o,SNAP_THRESHOLD+8,get(w,THRESHOLD_N))
        put(o,SNAP_NONCE,get(w,NONCE))
    return 0
''')
    source=replace_function(source,'reply',r'''
def reply(o:mutbuf,w:mutbuf) -> u32:
    clear(o,0,128)
    put(o,0,R)
    put(o,8,get(o,STATUS))
    put(o,16,get(o,SNAP_STATE))
    put(o,80,get(o,PENDING))
    put(o,88,get(o,KNOWN))
    put(o,96,get(o,CONSUMED))
    put(o,104,choose(get(o,SNAP_STATE)==4,1,0))
    put(o,112,get(o,DETAIL))
    put(o,120,get(o,SNAP_COUNT))
    clear(o,128,40)
    if get(o,DELIVERED)==1:
        put(o,24,get(o,CAP))
        put(o,32,get(o,CAP+8))
        put(o,40,get(o,CAP+16))
        i=0
        while i<1:
            put(o,48+i*8,get(o,SNAP_BANK+i*8))
            i=i+1
        put(o,72,get(o,SNAP_SOURCEFD))
        put(o,152,get(o,SNAP_NONCE))
    return 0
''')
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    tree=document(source_program(),'background_rank_proof_resource')
    p=ROOT/'examples/hia_bootstrap/background_rank_proof_resource.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
