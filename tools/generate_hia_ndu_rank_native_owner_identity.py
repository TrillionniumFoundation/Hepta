"""Private NDU owner JSON/identity role; source pins come from the frozen native receipt."""
from pathlib import Path
import ast,re,json,struct,hashlib
from tools.generate_hia_ndu_evaluator import document
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
def inspect(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<128 or length(w)<65536:
        return 4294967293
    mode=get(w,0)
    literals(w)
    zero(o,0,128)
    if mode==1:
        return bridge(s,o,w)
    if mode==2:
        put(w,8,0)
        end=match(s,w,0,white(s,0))
        if end==NONE or white(s,end)!=length(s):
            put(o,8,1)
        put(o,0,RECEIPT_MAGIC)
        return 128
    if mode==3:
        if length(s)!=8:
            return 4294967293
        index=word_load(s,0)
        if index>=SOURCE_COUNT:
            return 4294967295
        at=SOURCE_TABLE+index*64
        n=get(w,at)
        if length(o)<128+n:
            return 4294967293
        put(o,0,SOURCE_MAGIC)
        put(o,8,SOURCE_COUNT)
        put(o,16,n)
        put(o,24,get(w,at+8))
        copy(w,o,at+16,32,32)
        copy(w,o,get(w,at+48),128,n)
        return 128+n
    if mode==4:
        if length(o)<128+IDENTITY_SIZE:
            return 4294967293
        copy(w,o,IDENTITY_AT,128,IDENTITY_SIZE)
        put(o,0,IDENTITY_MAGIC)
        put(o,16,IDENTITY_SIZE)
        return 128+IDENTITY_SIZE
    return 4294967295

def bridge(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    put(o,0,BRIDGE_MAGIC)
    pos=white(s,0)
    if pos>=length(s) or byte(s,pos)!=123:
        put(o,8,1)
        return 128
    pos=white(s,pos+1)
    mask=0
    while pos<length(s) and byte(s,pos)!=125:
        key=key_kind(s,w,pos)
        if key==0:
            put(o,8,1)
            return 128
        end=string_end(s,pos)
        if end==NONE:
            put(o,8,1)
            return 128
        pos=white(s,end)
        if pos>=length(s) or byte(s,pos)!=58:
            put(o,8,1)
            return 128
        pos=white(s,pos+1)
        end=skip(s,pos)
        if end==NONE:
            put(o,8,1)
            return 128
        put(o,32+(key-1)*16,pos)
        put(o,40+(key-1)*16,end)
        mask=mask|(1<<(key-1))
        pos=white(s,end)
        if pos<length(s) and byte(s,pos)==44:
            pos=white(s,pos+1)
            if pos>=length(s) or byte(s,pos)==125:
                put(o,8,1)
                return 128
        else:
            if pos>=length(s) or byte(s,pos)!=125:
                put(o,8,1)
                return 128
    if mask!=3 or pos>=length(s) or white(s,pos+1)!=length(s):
        put(o,8,1)
        return 128
    i=0
    while i<2:
        p=get(o,32+i*16)
        if byte(s,p)!=34:
            put(o,8,2)
            put(o,16,i)
            put(o,24,value_type(s,p,get(o,40+i*16)))
            return 128
        i=i+1
    return 128

def value_type(s:readbuf,at:u64,end:u64) -> u64:
    ch=byte(s,at)
    if ch==78 or ch==73:
        return 4
    if ch==45 and at+1<end and byte(s,at+1)==73:
        return 4
    if ch==110:
        return 1
    if ch==116 or ch==102:
        return 2
    if ch==91:
        return 5
    if ch==123:
        return 6
    while at<end:
        ch=byte(s,at)
        if ch==46 or ch==101 or ch==69:
            return 4
        at=at+1
    return 3

def key_kind(s:readbuf,w:mutbuf,at:u64) -> u64:
    if same_string(s,w,at,BINARY_KEY,6)!=NONE:
        return 1
    if same_string(s,w,at,RECEIPT_KEY,13)!=NONE:
        return 2
    return 0

def match(s:readbuf,w:mutbuf,node:u64,at:u64) -> u64:
    at=white(s,at)
    if at>=length(s):
        return NONE
    row=NODE_TABLE+node*40
    kind=get(w,row)
    first=get(w,row+8)
    count=get(w,row+16)
    if kind==3:
        return same_string(s,w,at,first,count)
    if kind==4 or kind==5 or kind==6:
        i=0
        while i<count:
            if at+i>=length(s) or byte(s,at+i)!=byte(w,first+i):
                return NONE
            i=i+1
        end=at+count
        if end<length(s):
            ch=byte(s,end)
            if ch!=32 and ch!=9 and ch!=10 and ch!=13 and ch!=44 and ch!=93 and ch!=125:
                return NONE
        return end
    if kind==1:
        if byte(s,at)!=123:
            return NONE
        depth=get(w,8)
        if depth>=32:
            return NONE
        put(w,8,depth+1)
        put(w,512+depth*8,0)
        at=white(s,at+1)
        while at<length(s) and byte(s,at)!=125:
            i=0
            selected=NONE
            after=NONE
            while i<count:
                edge=EDGE_TABLE+(first+i)*24
                end=same_string(s,w,at,get(w,edge),get(w,edge+8))
                if end!=NONE:
                    selected=i
                    after=end
                i=i+1
            if selected==NONE or (get(w,512+depth*8)&(1<<selected))!=0:
                return NONE
            put(w,512+depth*8,get(w,512+depth*8)|(1<<selected))
            at=white(s,after)
            if at>=length(s) or byte(s,at)!=58:
                return NONE
            child=get(w,EDGE_TABLE+(first+selected)*24+16)
            at=match(s,w,child,at+1)
            if at==NONE:
                return NONE
            at=white(s,at)
            if at<length(s) and byte(s,at)==44:
                at=white(s,at+1)
                if at>=length(s) or byte(s,at)==125:
                    return NONE
            else:
                if at>=length(s) or byte(s,at)!=125:
                    return NONE
        if at>=length(s) or get(w,512+depth*8)!=(1<<count)-1:
            return NONE
        put(w,8,depth)
        return at+1
    if kind==2:
        if byte(s,at)!=91:
            return NONE
        at=white(s,at+1)
        i=0
        while i<count:
            child=get(w,EDGE_TABLE+(first+i)*24+16)
            at=match(s,w,child,at)
            if at==NONE:
                return NONE
            at=white(s,at)
            i=i+1
            if i<count:
                if at>=length(s) or byte(s,at)!=44:
                    return NONE
                at=white(s,at+1)
        if at>=length(s) or byte(s,at)!=93:
            return NONE
        return at+1
    return NONE

def same_string(s:readbuf,w:mutbuf,at:u64,expected:u64,n:u64) -> u64:
    if at>=length(s) or byte(s,at)!=34:
        return NONE
    at=at+1
    i=0
    while at<length(s) and byte(s,at)!=34:
        ch=byte(s,at)
        at=at+1
        if ch==92:
            if at>=length(s):
                return NONE
            ch=byte(s,at)
            at=at+1
            if ch==117:
                if length(s)-at<4:
                    return NONE
                value=0
                j=0
                while j<4:
                    digit=hex_value(byte(s,at+j))
                    if digit==16:
                        return NONE
                    value=value*16+digit
                    j=j+1
                ch=value
                at=at+4
            else:
                if ch==98:
                    ch=8
                elif ch==102:
                    ch=12
                elif ch==110:
                    ch=10
                elif ch==114:
                    ch=13
                elif ch==116:
                    ch=9
                elif ch!=34 and ch!=47 and ch!=92:
                    return NONE
        elif ch<32:
            return NONE
        if i>=n or ch!=byte(w,expected+i):
            return NONE
        i=i+1
    if at>=length(s) or i!=n:
        return NONE
    return at+1

def string_end(s:readbuf,at:u64) -> u64:
    if at>=length(s) or byte(s,at)!=34:
        return NONE
    at=at+1
    while at<length(s):
        ch=byte(s,at)
        at=at+1
        if ch==34:
            return at
        if ch==92:
            if at>=length(s):
                return NONE
            at=at+1
    return NONE

def skip(s:readbuf,at:u64) -> u64:
    if at>=length(s):
        return NONE
    if byte(s,at)==34:
        return string_end(s,at)
    if byte(s,at)==123 or byte(s,at)==91:
        depth=0
        while at<length(s):
            ch=byte(s,at)
            if ch==34:
                at=string_end(s,at)
                if at==NONE:
                    return NONE
            else:
                at=at+1
                if ch==123 or ch==91:
                    depth=depth+1
                elif ch==125 or ch==93:
                    depth=depth-1
                    if depth==0:
                        return at
        return NONE
    while at<length(s):
        ch=byte(s,at)
        if ch==32 or ch==9 or ch==10 or ch==13 or ch==44 or ch==93 or ch==125:
            return at
        at=at+1
    return at

def white(s:readbuf,at:u64) -> u64:
    while at<length(s):
        ch=byte(s,at)
        if ch!=32 and ch!=9 and ch!=10 and ch!=13:
            return at
        at=at+1
    return at

def hex_value(ch:u64) -> u64:
    if ch>=48 and ch<=57:
        return ch-48
    if ch>=65 and ch<=70:
        return ch-55
    if ch>=97 and ch<=102:
        return ch-87
    return 16

def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)

def put(w:mutbuf,at:u64,value:u64) -> u64:
    word_store(w,at,value)
    return 0

def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0

def copy(w:mutbuf,o:mutbuf,at:u64,to:u64,n:u64) -> u64:
    i=0
    while n-i>=8:
        word_store(o,to+i,word_load(w,at+i))
        i=i+8
    while i<n:
        store(o,to+i,byte(w,at+i))
        i=i+1
    return 0
'''
def program():
    receipt=json.loads((ROOT/'docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json').read_text())
    nodes=[];edges=[];pool=bytearray();POOL=32768;NODE=8192;EDGE=16384;ST=24576
    def string(b):
        at=POOL+len(pool);pool.extend(b);return at,len(b)
    def node(v):
        index=len(nodes);nodes.append(None)
        if isinstance(v,dict):
            assert len(v)<64
            es=[(*string(k.encode()),node(x))for k,x in v.items()];first=len(edges);edges.extend(es);nodes[index]=(1,first,len(es),0,0)
        elif isinstance(v,list):
            es=[(0,0,node(x))for x in v];first=len(edges);edges.extend(es);nodes[index]=(2,first,len(es),0,0)
        elif isinstance(v,str):at,n=string(v.encode());nodes[index]=(3,at,n,0,0)
        else:
            b=json.dumps(v,separators=(',',':')).encode();at,n=string(b);nodes[index]=(4,at,n,0,0)
        return index
    node(receipt)
    assert NODE+40*len(nodes)<=EDGE and EDGE+24*len(edges)<=ST
    files=[]
    for p,h in receipt['source_files'].items():
        at,n=string(p.encode());files.append(struct.pack('<QQ32sQQ',n,(ROOT/p).stat().st_size,bytes.fromhex(h),at,0))
    ident={'upstream_commit':receipt['upstream_commit'],'build_inputs_sha256':receipt['build_inputs_sha256'],'source_attestation':'trusted_local_native_build_receipt'}
    ia,inn=string(json.dumps(ident,sort_keys=True,separators=(',',':')).encode())
    bk,_=string(b'binary');rk,_=string(b'build_receipt')
    assert POOL+len(pool)<65536
    blob=bytearray(65536)
    for i,r in enumerate(nodes):struct.pack_into('<5Q',blob,NODE+i*40,*r)
    for i,r in enumerate(edges):struct.pack_into('<3Q',blob,EDGE+i*24,*r)
    for i,r in enumerate(files):blob[ST+i*64:ST+(i+1)*64]=r
    blob[POOL:POOL+len(pool)]=pool
    parts=[];used=[]
    for base in range(8192,65536,512):
        words=[(at,int.from_bytes(blob[at:at+8],'little'))for at in range(base,base+512,8)if any(blob[at:at+8])]
        if not words:continue
        name='literal_'+str(len(used));used.append(name);p=[f'def {name}(w:mutbuf) -> u64:']
        for at,v in words:p.append(f'    word_store(w,{at},{v})')
        p.append('    return 0');parts.append('\n'.join(p))
    p=['def literals(w:mutbuf) -> u64:','    zero(w,8192,57344)']+[f'    {n}(w)'for n in used]+['    return 0'];parts.insert(0,'\n'.join(p))
    C={'NONE':2**64-1,'NODE_TABLE':NODE,'EDGE_TABLE':EDGE,'SOURCE_TABLE':ST,'SOURCE_COUNT':len(files),'BINARY_KEY':bk,'RECEIPT_KEY':rk,'IDENTITY_AT':ia,'IDENTITY_SIZE':inn,'RECEIPT_MAGIC':int.from_bytes(b'HIANRI01','little'),'BRIDGE_MAGIC':int.from_bytes(b'HIANBI01','little'),'SOURCE_MAGIC':int.from_bytes(b'HIANSF01','little'),'IDENTITY_MAGIC':int.from_bytes(b'HIANID01','little')}
    s=SOURCE+'\n\n'+'\n\n'.join(parts)
    for name,v in C.items():s=re.sub(r'\b'+name+r'\b',str(v),s)
    return s
def render():return render_assembly(document(program(),'ndu_rank_native_owner_identity'))
if __name__=='__main__':
    p=ROOT/'examples/hia_bootstrap/ndu_rank_native_owner_identity.hepta';doc=document(program(),'ndu_rank_native_owner_identity');p.write_text(render_assembly(doc));print(p.name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']))
