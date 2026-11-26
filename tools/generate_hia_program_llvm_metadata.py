"""Read the actual completed native LLVM workspace's export decisions."""
from tools.generate_hia_program_llvm_common import write_module
SOURCE=r'''
def metadata(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=32 or word(s,0)!=3544406887218235720:
        return 4294967293
    if word(s,8)!=0 or word(s,16)!=0 or word(s,24)!=0:
        return 4294967293
    if length(w)<WORK or length(o)<64:
        return 4294967293
    if get(w,PHASE)!=13 or get(w,ERROR)!=0 or get(w,OUTPUT_SIZE)==0 or get(w,OUTPUT_SIZE)>MAX_IR:
        return 4294967293
    n=get(w,WRAPPER_COUNT)
    if n==0 or n>128 or get(w,FUNCTION_COUNT)>1024 or get(w,VERSION)==0 or get(w,VERSION)>9:
        return 4294967293
    cursor=0
    used=0
    needed=64
    while cursor<get(w,FUNCTION_COUNT):
        fn=get(w,FUNCS+cursor*8)
        if meta(w,fn,72)==1:
            name=field(w,fn,K_name)
            if identifier(w,name)==0 or used>=n:
                return 4294967293
            put(w,CTRL+3072+used*8,name)
            needed=needed+8+count(w,name)
            used=used+1
        cursor=cursor+1
    if used!=n or needed>length(o):
        return 4294967294
    i=1
    while i<n:
        name=get(w,CTRL+3072+i*8)
        j=i
        moving=1
        while j>0 and moving==1:
            before=get(w,CTRL+3072+(j-1)*8)
            if text_less(w,name,before)==1:
                put(w,CTRL+3072+j*8,before)
                j=j-1
            else:
                moving=0
        put(w,CTRL+3072+j*8,name)
        i=i+1
    i=0
    while i<64:
        store(o,i,0)
        i=i+1
    put(o,0,3544412384776374600)
    put(o,8,get(w,VERSION))
    put(o,16,get(w,TARGET))
    put(o,24,get(w,LAYOUT))
    put(o,32,n)
    put(o,40,get(w,OUTPUT_SIZE))
    put(o,48,needed-64)
    at=64
    i=0
    while i<n:
        name=get(w,CTRL+3072+i*8)
        size=count(w,name)
        pos=get(w,64+name*56+24)
        put(o,at,size)
        at=at+8
        j=0
        while j<size:
            store(o,at+j,byte(w,pos+j))
            j=j+1
        at=at+size
        i=i+1
    return at

def text_less(w:mutbuf,a:u64,b:u64) -> u64:
    an=count(w,a)
    bn=count(w,b)
    ap=get(w,64+a*56+24)
    bp=get(w,64+b*56+24)
    i=0
    while i<an and i<bn:
        x=byte(w,ap+i)
        y=byte(w,bp+i)
        if x<y:
            return 1
        if x>y:
            return 0
        i=i+1
    if an<bn:
        return 1
    return 0
'''
# The wire constants are written explicitly by the author, not inferred from a
# purported version suffix or a caller's authority flag.
SOURCE=SOURCE.replace('3544406887218235720',str(int.from_bytes(b'HIALLM01','little')))
SOURCE=SOURCE.replace('3544412384776374600',str(int.from_bytes(b'HIALLR01','little')))
if __name__=='__main__':write_module('program_llvm_metadata',SOURCE,'metadata')
