"""Pure native inventory refusal text and original Unicode error facts.

The wire contains only immutable artifact bytes, actual inventory data and
source export names. It carries no capabilities, addresses or authority bits.
"""
from tools.generate_hia_clang_capture_common import write_module
SOURCE=r'''
def describe(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<1048704:
        return 4294967294
    if length(s)<128 or word(s,0)!=0x3152454943414948 or word(s,8)>1:
        return 4294967293
    i=48
    while i<128:
        if word(s,i)!=0:
            return 4294967293
        i=i+8
    art=word(s,16)
    inv=word(s,24)
    expected=word(s,40)
    if art==0 or art>67108864 or art>length(s)-128 or inv>length(s)-128-art:
        return 4294967293
    if expected!=length(s)-128-art-inv or inv<64 or word(s,32)>128:
        return 4294967293
    clear(w,0,128)
    put(w,0,word(s,8))
    put(w,32,art)
    put(w,40,128+art)
    put(w,48,inv)
    put(w,64,128+art+inv)
    put(w,72,word(s,32))
    put(w,80,expected)
    if expected_valid(s,w)==False:
        return 4294967293
    valid=False
    if word(s,8)==0:
        valid=shared_error(s,w)
    else:
        valid=object_error(s,w)
    if valid==False:
        return 4294967293
    reason=get(w,16)
    n=text_length(reason)
    if reason==32:
        n=n+expected_length(s,w)+text_length(33)+observed_length(s,w)
    elif reason>=29 and reason<=31:
        n=n+get(w,104)
    if n>134217728:
        return 4294967293
    put(w,56,128+n)
    if length(o)<128+n:
        return 4294967294
    clear(o,0,128)
    put(o,0,0x3153524943414948)
    put(o,8,get(w,24))
    put(o,16,n)
    put(o,24,get(w,120))
    put(o,32,get(w,96))
    put(o,40,get(w,104))
    put(o,48,get(w,112))
    put(o,56,128+n)
    at=text_copy(o,128,reason)
    if reason==32:
        at=expected_copy(s,o,w,at)
        at=text_copy(o,at,33)
        at=observed_copy(s,o,w,at)
    elif reason>=29 and reason<=31:
        at=copy_bytes(s,o,128+get(w,96),at,get(w,104))
    if at!=128+n:
        return 4294967293
    return 128+n

def uint(s:readbuf,at:u64,n:u64) -> u64:
    value=0
    i=0
    while i<n:
        value=value|(byte(s,at+i)<<(8*i))
        i=i+1
    return value

def inside(total:u64,at:u64,n:u64) -> bool:
    return at<=total and n<=total-at

def identifier(s:readbuf,at:u64,n:u64) -> bool:
    if n==0 or n>512 or inside(length(s),at,n)==False:
        return False
    i=0
    while i<n:
        c=byte(s,at+i)
        if (c==95 or c>=65 and c<=90 or c>=97 and c<=122 or i!=0 and c>=48 and c<=57)==False:
            return False
        i=i+1
    return True

def expected_valid(s:readbuf,w:mutbuf) -> bool:
    at=get(w,64)
    i=0
    previous=0
    previous_n=0
    while i<get(w,72):
        if inside(length(s),at,8)==False:
            return False
        n=word(s,at)
        at=at+8
        if identifier(s,at,n)==False:
            return False
        if i!=0 and byte_before(s,previous,previous_n,at,n)==False:
            return False
        previous=at
        previous_n=n
        at=at+n
        i=i+1
    return at==length(s)

def shared_error(s:readbuf,w:mutbuf) -> bool:
    at=get(w,40)
    code=word(s,at)
    if code>31:
        return False
    put(w,8,code)
    put(w,16,code)
    put(w,24,51)
    if code==1 and get(w,32)<64:
        put(w,16,34)
    i=24
    while i<64:
        if word(s,at+i)!=0:
            return False
        i=i+8
    if code==0:
        if word(s,at+16)!=2 or word(s,at+8)>65536 or get(w,48)!=2112+word(s,at+8)*24:
            return False
        put(w,16,32)
        return collect_exports(s,w)
    if get(w,48)!=64:
        return False
    if code>=29:
        name=word(s,at+8)
        n=word(s,at+16)
        if inside(get(w,32),name,n+1)==False or identifier(s,128+name,n)==False:
            return False
        put(w,96,name)
        put(w,104,n)
    else:
        if word(s,at+8)!=0 or word(s,at+16)!=0:
            return False
        if code==25:
            return find_nonascii(s,w,11,18446744073709551615)
    return True

def object_error(s:readbuf,w:mutbuf) -> bool:
    at=get(w,40)
    if get(w,48)!=64 or word(s,at)!=0x313052454f414948 or word(s,at+48)!=0 or word(s,at+56)!=0:
        return False
    code=word(s,at+8)
    pos=word(s,at+40)
    if code==0 or code>13:
        return False
    put(w,8,code)
    put(w,24,52)
    reason=64
    if code==2:
        reason=68
        if pos!=0:
            if pos<64 or inside(get(w,32),pos-64,64)==False:
                return False
            kind=uint(s,128+pos-64+4,4)
            reason=66
            if kind==2:
                reason=65
            elif kind==3:
                reason=67
    elif code>=3 and code<=6:
        reason=66+code
        if code==5 and find_nonascii(s,w,2,pos)==False:
            return False
    elif code==7:
        if pos<64 or inside(get(w,32),pos-64,24)==False:
            return False
        reason=74
        if uint(s,128+pos-64+6,2)==0:
            reason=73
    elif code==8:
        reason=75
    elif code==9:
        if get(w,32)<64 or pos<64 or inside(get(w,32),pos-64,24)==False:
            return False
        reason=77
        if uint(s,128+pos-64+6,2)>=uint(s,128+60,2):
            reason=76
    elif code>=10:
        reason=68+code
        if code>=12:
            put(w,24,45)
    put(w,16,reason)
    return True

def find_nonascii(s:readbuf,w:mutbuf,symbol_kind:u64,wanted:u64) -> bool:
    total=get(w,32)
    if total<64:
        return False
    table=word(s,128+40)
    count=uint(s,128+60,2)
    if count==0 or count>4096 or inside(total,table,count*64)==False:
        return False
    i=0
    while i<count:
        row=128+table+i*64
        if uint(s,row+4,4)==symbol_kind:
            code=table_nonascii(s,w,row,wanted)
            if code==0:
                return False
            if code==2:
                return True
        i=i+1
    return False

def table_nonascii(s:readbuf,w:mutbuf,row:u64,wanted:u64) -> u64:
    total=get(w,32)
    table=word(s,128+40)
    count=uint(s,128+60,2)
    start=word(s,row+24)
    n=word(s,row+32)
    link=uint(s,row+40,4)
    if n%24!=0 or word(s,row+56)!=24 or link>=count or inside(total,start,n)==False:
        return 0
    names_row=128+table+link*64
    names=word(s,names_row+24)
    names_n=word(s,names_row+32)
    if uint(s,names_row+4,4)!=3 or inside(total,names,names_n)==False:
        return 0
    j=0
    while j<n:
        pos=start+j
        if wanted==18446744073709551615 or wanted==pos+64:
            code=name_nonascii(s,w,pos,names,names_n)
            if code!=1:
                return code
        j=j+24
    return 1

def name_nonascii(s:readbuf,w:mutbuf,pos:u64,names:u64,names_n:u64) -> u64:
    off=uint(s,128+pos,4)
    if off==0:
        return 1
    if off>=names_n:
        return 0
    size=0
    bad=18446744073709551615
    while size<names_n-off:
        c=byte(s,128+names+off+size)
        if c==0:
            if bad==18446744073709551615:
                return 1
            put(w,96,names+off)
            put(w,104,size)
            put(w,112,bad)
            put(w,120,1)
            return 2
        if bad==18446744073709551615 and c>=128:
            bad=size
        size=size+1
    return 0

def collect_exports(s:readbuf,w:mutbuf) -> bool:
    at=get(w,40)
    count=word(s,at+8)
    i=0
    found=0
    while i<count:
        row=at+2112+i*24
        name=word(s,row)
        n=word(s,row+8)
        kind=word(s,row+16)
        if kind>1 or inside(get(w,32),name,n+1)==False or identifier(s,128+name,n)==False:
            return False
        if kind==1:
            put(w,128+found*8,row)
            found=found+1
        i=i+1
    put(w,88,found)
    width=1
    while width<found:
        start=0
        while start<found:
            mid=start+width
            if mid>found:
                mid=found
            end=mid+width
            if end>found:
                end=found
            left=start
            right=mid
            out=start
            while out<end:
                use_left=False
                if right==end:
                    use_left=True
                elif left<mid:
                    use_left=row_before(s,get(w,128+left*8),get(w,128+right*8))
                if use_left:
                    put(w,524416+out*8,get(w,128+left*8))
                    left=left+1
                else:
                    put(w,524416+out*8,get(w,128+right*8))
                    right=right+1
                out=out+1
            start=end
        i=0
        while i<found:
            put(w,128+i*8,get(w,524416+i*8))
            i=i+1
        width=width*2
    i=1
    while i<found:
        if row_before(s,get(w,128+(i-1)*8),get(w,128+i*8))==False:
            return False
        i=i+1
    return True

def row_before(s:readbuf,a:u64,b:u64) -> bool:
    return byte_before(s,128+word(s,a),word(s,a+8),128+word(s,b),word(s,b+8))

def byte_before(s:readbuf,a:u64,an:u64,b:u64,bn:u64) -> bool:
    i=0
    while i<an and i<bn:
        x=byte(s,a+i)
        y=byte(s,b+i)
        if x!=y:
            return x<y
        i=i+1
    return an<bn

def expected_length(s:readbuf,w:mutbuf) -> u64:
    n=2
    at=get(w,64)
    i=0
    while i<get(w,72):
        size=word(s,at)
        n=n+size+2
        if i!=0:
            n=n+2
        at=at+8+size
        i=i+1
    if get(w,72)==1:
        n=n+1
    return n

def observed_length(s:readbuf,w:mutbuf) -> u64:
    n=2
    i=0
    while i<get(w,88):
        n=n+word(s,get(w,128+i*8)+8)+2
        if i!=0:
            n=n+2
        i=i+1
    if get(w,88)==1:
        n=n+1
    return n

def expected_copy(s:readbuf,o:mutbuf,w:mutbuf,at:u64) -> u64:
    store(o,at,40)
    at=at+1
    input=get(w,64)
    i=0
    while i<get(w,72):
        n=word(s,input)
        input=input+8
        if i!=0:
            store(o,at,44)
            store(o,at+1,32)
            at=at+2
        store(o,at,39)
        at=copy_bytes(s,o,input,at+1,n)
        store(o,at,39)
        at=at+1
        input=input+n
        i=i+1
    if get(w,72)==1:
        store(o,at,44)
        at=at+1
    store(o,at,41)
    return at+1

def observed_copy(s:readbuf,o:mutbuf,w:mutbuf,at:u64) -> u64:
    store(o,at,40)
    at=at+1
    i=0
    while i<get(w,88):
        row=get(w,128+i*8)
        if i!=0:
            store(o,at,44)
            store(o,at+1,32)
            at=at+2
        store(o,at,39)
        at=copy_bytes(s,o,128+word(s,row),at+1,word(s,row+8))
        store(o,at,39)
        at=at+1
        i=i+1
    if get(w,88)==1:
        store(o,at,44)
        at=at+1
    store(o,at,41)
    return at+1

def copy_bytes(s:readbuf,o:mutbuf,input:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,byte(s,input+i))
        i=i+1
    return at+n
'''
TEXTS={
 "1": "E_LLVM_OWNED_DYNSYM: not Linux/x86-64 ELF64 ET_DYN",
 "2": "E_LLVM_OWNED_DYNSYM: missing or out-of-file ELF section table",
 "3": "E_LLVM_OWNED_DYNSYM: section points outside artifact",
 "4": "E_LLVM_OWNED_DYNSYM: missing or invalid program headers",
 "5": "E_LLVM_OWNED_DYNSYM: PT_INTERP or PT_TLS is outside the checked shared-library profile",
 "6": "E_LLVM_OWNED_DYNSYM: PT_GNU_STACK requires reviewed non-executable RW permissions",
 "7": "E_LLVM_OWNED_DYNSYM: invalid loader dynamic table bounds",
 "8": "E_LLVM_OWNED_DYNSYM: PT_LOAD has unreviewed permissions or is writable-executable",
 "9": "E_LLVM_OWNED_DYNSYM: invalid load segment range",
 "10": "E_LLVM_OWNED_DYNSYM: missing or duplicated explicit non-executable PT_GNU_STACK",
 "11": "E_LLVM_OWNED_DYNSYM: no executable load segment",
 "12": "E_LLVM_OWNED_DYNSYM: missing or duplicated PT_DYNAMIC loader table",
 "13": "E_LLVM_OWNED_DYNSYM: expected exactly one dynamic symbol table",
 "14": "E_LLVM_OWNED_DYNSYM: invalid dynamic symbols or string table",
 "15": "E_LLVM_OWNED_DYNSYM: unbounded loader dynamic table",
 "16": "E_LLVM_OWNED_DYNSYM: unreviewed dynamic loader redirect, audit, filter or text-relocation tag",
 "17": "E_LLVM_OWNED_DYNSYM: DT_FLAGS enables unreviewed origin, symbolic binding or text relocations",
 "18": "E_LLVM_OWNED_DYNSYM: DT_FLAGS_1 enables unreviewed loader side effects",
 "19": "E_LLVM_OWNED_DYNSYM: duplicate loader symbol metadata",
 "20": "E_LLVM_OWNED_DYNSYM: loader dynamic symbol/string authority disagrees with ELF sections",
 "21": "E_LLVM_OWNED_DYNSYM: unbounded loader dependency",
 "22": "E_LLVM_OWNED_DYNSYM: unreviewed DT_NEEDED shared library dependency",
 "23": "E_LLVM_OWNED_DYNSYM: dynamic string name points outside table",
 "24": "E_LLVM_OWNED_DYNSYM: unterminated dynamic symbol name",
 "25": "E_LLVM_OWNED_DYNSYM: non-ASCII dynamic symbol",
 "26": "E_LLVM_OWNED_DYNSYM: unknown/empty dynamic symbol spelling",
 "27": "E_LLVM_OWNED_DYNSYM: unknown dynamic symbol binding",
 "28": "E_LLVM_OWNED_DYNSYM: duplicate external symbol identity",
 "29": "E_LLVM_OWNED_DYNSYM: unreviewed external import: ",
 "30": "E_LLVM_OWNED_DYNSYM: unknown, repeated, or invalid public function export: ",
 "31": "E_LLVM_OWNED_DYNSYM: export not wholly inside executable file-backed code: ",
 "32": "E_LLVM_OWNED_DYNSYM: public ABI symbols differ from source: expected ",
 "33": ", observed ",
 "34": "E_LLVM_OWNED_DYNSYM: invalid artifact or source export list",
 "64": "E_OBJECT_SYMBOL_SHAPE: unqualified object structure",
 "65": "E_OBJECT_SYMBOL_TABLE: invalid ELF symbol inventory",
 "66": "E_OBJECT_SYMBOL_TABLE: ELF symbol strings missing",
 "67": "E_OBJECT_SYMBOL_TABLE: ELF names outside file",
 "68": "E_OBJECT_SYMBOL_TABLE: no ELF symbol table",
 "69": "E_OBJECT_SYMBOL_NAME: bad ELF name",
 "70": "E_OBJECT_SYMBOL_NAME: unterminated name",
 "71": "E_OBJECT_SYMBOL_NAME: non-ASCII symbol",
 "72": "E_OBJECT_SYMBOL_EXPORT_KIND: unreviewed ELF symbol binding",
 "73": "E_OBJECT_SYMBOL_DUPLICATE: export also imported",
 "74": "E_OBJECT_SYMBOL_DUPLICATE: ELF function identity reused",
 "75": "E_OBJECT_SYMBOL_WEAK: checked C function export cannot be interposed",
 "76": "E_OBJECT_SYMBOL_LOCATION: invalid ELF function section",
 "77": "E_OBJECT_SYMBOL_LOCATION: ELF function outside executable section",
 "78": "E_OBJECT_SYMBOL_EXPORT_KIND: unexpected defined ELF global",
 "79": "E_OBJECT_SYMBOL_EXPORT: no defined function exports",
 "80": "E_HIA_PROGRAM_LLVM: object import/export inventory differs from the closed core ABI",
 "81": "E_HIA_PROGRAM_LLVM: RISC-V object requires the reviewed RV64GC LP64D ELF flags"
}
def source():
 text=SOURCE+'\ndef text_length(reason:u64) -> u64:\n'
 for key,value in TEXTS.items():text+='    if reason=='+str(key)+':\n        return '+str(len(value.encode('ascii')))+'\n'
 text+='    return 0\n\ndef text_copy(o:mutbuf,at:u64,reason:u64) -> u64:\n'
 for key in TEXTS:text+='    if reason=='+str(key)+':\n        return text_'+str(key)+'(o,at)\n'
 text+='    return at\n'
 for key,value in TEXTS.items():
  raw=value.encode('ascii');text+='\ndef text_'+str(key)+'(o:mutbuf,at:u64) -> u64:\n'
  i=0
  while len(raw)-i>=8:
   text+='    put(o,at+'+str(i)+','+str(int.from_bytes(raw[i:i+8],'little'))+')\n';i+=8
  for j in range(i,len(raw)):text+='    store(o,at+'+str(j)+','+str(raw[j])+')\n'
  text+='    return at+'+str(len(raw))+'\n'
 return text
if __name__=='__main__':write_module('clang_inventory_error_text',source(),'describe')
