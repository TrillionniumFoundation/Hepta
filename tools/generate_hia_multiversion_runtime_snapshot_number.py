"""Lossless retained lease-count binary to decimal; no numeric word ceiling."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
def snapshot_number(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=length(s)
    if n==0 or n>6148914691236517183 or length(w)<64:
        return 4294967293
    if n>1 and byte(s,n-1)==0:
        return 4294967293
    cap=n*3+1
    if cap>18446744073709551551:
        return 4294967293
    put(w,8,64+cap)
    if length(w)<64+cap:
        return 4294967292
    store(w,64,0)
    used=1
    i=n
    while i>0:
        i=i-1
        carry=byte(s,i)
        j=0
        while j<used:
            value=byte(w,64+j)*256+carry
            store(w,64+j,value-divide10(value)*10)
            carry=divide10(value)
            j=j+1
        while carry!=0:
            if used>=cap:
                return 4294967293
            store(w,64+used,carry-divide10(carry)*10)
            used=used+1
            carry=divide10(carry)
    put(w,0,used)
    if length(o)<used:
        return 4294967294
    j=0
    while j<used:
        store(o,j,byte(w,64+used-1-j)+48)
        j=j+1
    return 0

def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,value>>(i*8))
        i=i+1
    return 0
def divide10(value:u64) -> u64:
    q=(value>>1)+(value>>2)
    q=q+(q>>4)
    q=q+(q>>8)
    q=q+(q>>16)
    q=q+(q>>32)
    q=q>>3
    r=value-q*10
    if r>=10:
        q=q+1
    return q

'''
def main():
 t=document(SOURCE,'multiversion_runtime_snapshot_number')
 p=ROOT/'examples/hia_bootstrap/multiversion_runtime_snapshot_number.hepta'
 p.write_text(render_assembly(t))
 print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
