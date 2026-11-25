"""Native mechanical six-view and full-u64 return binding for MV snapshots."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document as author_document
ROOT=Path(__file__).resolve().parents[1]
PREFIX=bytes.fromhex('4154415541564d89c44989fd4901f572784989d64901ce72704d89c34d01cb72684885f674054885ff745e4885c974054885d274544d85c974054d85c0744a4885f6741e4885c9740a4c39f773054c39ea72364d85c9740a4c39df73054d39e872274885c9740f4d85c9740a4c39da73054d39f07213e83400000085c0742583f8fe740e83f8fc741248c7c0ffffffffeb1648c7c0feffffffeb0d48c7c0fdffffffeb04498b0424415e415d415cc3')
SOURCE=r'''
def snapshot_packer(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<33 or length(w)<64:
        return 4294967293
    if word_load(s,0)!=MAGIC or word_load(s,16)!=0 or word_load(s,24)!=0:
        return 4294967293
    n=word_load(s,8)
    if n==0 or n>4194304 or n!=length(s)-32:
        return 4294967293
    need=n+PREFIX_BYTES
    word_store(w,0,need)
    if length(o)<need:
        return 4294967294
    PREFIX_WRITES
    i=0
    while i<n:
        store(o,PREFIX_BYTES+i,byte(s,32+i))
        i=i+1
    return 0
'''
def document():
    writes=[]
    for i in range(0,len(PREFIX),8):
        q=PREFIX[i:i+8]
        if len(q)==8:writes.append('word_store(o,'+str(i)+','+str(int.from_bytes(q,'little'))+')')
        else:
            for j,b in enumerate(q):writes.append('store(o,'+str(i+j)+','+str(b)+')')
    source=SOURCE.replace('PREFIX_WRITES','\n    '.join(writes)).replace('PREFIX_BYTES',str(len(PREFIX))).replace('MAGIC',str(int.from_bytes(b'HIAMVSPK','little')))
    return author_document(source,'multiversion_runtime_snapshot_packer')
def main():
    p=ROOT/'examples/hia_bootstrap/multiversion_runtime_snapshot_packer.hepta';j=document();p.write_text(render_assembly(j))
    print('snapshot_packer',p.stat().st_size,len(j['functions']),sum(len(f['blocks'])for f in j['functions']),sum(len(b['ops'])for f in j['functions']for b in f['blocks']))
if __name__=='__main__':main()
