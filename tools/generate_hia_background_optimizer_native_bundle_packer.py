"""Native fixed BG DSO packer.

Every input is a bounded native leaf or an already native-built canonical ELF
capsule. The rank engine is expanded into its original 21 bounded leaf inputs.
The output has one static table, four fixed exports and only the four retained
platform imports. It never embeds a second Value or Future provider.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
from tools import generate_hia_ndu_rank_engine_packer as rank
from tools import generate_hia_background_optimizer_native_fixed_context_packer as context
from tools.generate_hia_background_optimizer_native_context import ENTRY_NAMES
ROOT=Path(__file__).resolve().parents[1]
ROLES=tuple(n for n in ENTRY_NAMES if n not in('rank','future_provider_deferred'))+('context','public')+tuple('rank_'+n for n in rank.ROLES)
assert len(ROLES)==61
BARE={'path_error','path_string_codec','json_capture','sha256','checked_freezer','verify_raw','structure_compat','admission','decision_policy'}
OBJECT_MASK=sum(1<<i for i,n in enumerate(ROLES)if n not in BARE and not n.startswith('rank_'))
MAGIC=int.from_bytes(b'HIABGBP1','little');HEADER=16+8*len(ROLES)
IMPORTS=('malloc','free','pthread_create','pthread_join')
EXPORTS=(('hia_background_native_public',0),('hia_background_native_context',16),
         ('hia_background_native_finalizer',32),('hia_background_native_registry',48))
RANK_AT=64
BRIDGE=(b'\xe9'+bytes(15))*4+rank.BRIDGE
ELF_HEADER=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
def fixed_metadata():
    strings=bytearray(b'\0');pos={}
    for name in [n for n,_ in EXPORTS]+list(IMPORTS):
        pos[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0)]
    for n,at in EXPORTS:symbols.append(struct.pack('<IBBHQQ',pos[n],18,0,1,at,5))
    for n in IMPORTS:symbols.append(struct.pack('<IBBHQQ',pos[n],16,0,0,0,0))
    rows=[bytes(64)]
    for name,kind,flags,link,info,align,extent in [
      ('.text',1,6,0,0,16,0),('.rela.text',4,0,3,1,8,24),('.symtab',2,0,4,2,8,24),
      ('.strtab',3,0,0,0,1,0),('.shstrtab',3,0,0,0,1,0),('.note.GNU-stack',1,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,0,link,info,align,extent))
    return b''.join(symbols),bytes(strings),b''.join(rows)
def inspect_object(raw):
    if len(raw)<512 or raw[:40]!=ELF_HEADER[:40]or raw[48:64]!=ELF_HEADER[48:64]:
        raise ValueError('canonical ELF header required')
    sh=struct.unpack_from('<Q',raw,40)[0]
    if sh>len(raw)-448 or sh+448!=len(raw):raise ValueError('exact section tail required')
    rows=[struct.unpack_from('<IIQQQQIIQQ',raw,sh+i*64)for i in range(7)]
    meta=struct.unpack_from
    if rows[0]!=tuple([0]*10):raise ValueError('null section')
    for i,(name,kind,flags,link,info,align,extent)in enumerate([
      ('.text',1,6,0,0,16,0),('.rela.text',4,0,3,1,8,24),('.symtab',2,0,4,2,8,24),
      ('.strtab',3,0,0,0,1,0),('.shstrtab',3,0,0,0,1,0),('.note.GNU-stack',1,0,0,0,1,0)],1):
        r=rows[i]
        if (r[0],r[1],r[2],r[3],r[6],r[7],r[8],r[9])!=(base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,link,info,align,extent):
            raise ValueError('fixed section grammar')
    tn=rows[1][5]
    if rows[1][4]!=64 or not 0<tn<=4194304:raise ValueError('text bound')
    at=(64+tn+7)&~7
    if any(raw[64+tn:at]):raise ValueError('text padding')
    for i in range(2,6):
        if rows[i][4]!=at:raise ValueError('section order')
        at+=rows[i][5]
    if rows[6][4]!=at or rows[6][5]!=0 or sh!=(at+7)&~7 or any(raw[at:sh]):raise ValueError('note/padding')
    rn,sn,stn=rows[2][5],rows[3][5],rows[4][5]
    if rn%24 or rn//24>256 or sn%24 or not 48<=sn<=6144 or not 0<stn<=65536:raise ValueError('table bounds')
    if rows[5][5]!=len(base.SECTIONS)or raw[rows[5][4]:rows[5][4]+rows[5][5]]!=base.SECTIONS:raise ValueError('section names')
    sy,st=rows[3][4],rows[4][4]
    if raw[sy:sy+24]!=bytes(24)or raw[sy+24:sy+48]!=struct.pack('<IBBHQQ',0,3,0,1,0,0)or raw[st]!=0:raise ValueError('null symbols')
    symbols=[]
    for i in range(sn//24):
        q=struct.unpack_from('<IBBHQQ',raw,sy+24*i)
        if i<2:symbols.append(None);continue
        name,info,other,section,value,size=q
        if name==0 or name>=stn or other!=0:raise ValueError('symbol shape')
        end=raw.find(b'\0',st+name,st+stn)
        if end<0:raise ValueError('symbol termination')
        text=raw[st+name:end].decode('ascii')
        if info==16:
            if section or value or size or text not in IMPORTS:raise ValueError('fixed import')
        elif info==18:
            if section!=1 or value>tn or size>tn-value:raise ValueError('export span')
        else:raise ValueError('symbol kind')
        symbols.append((q,text))
    rels=[]
    for i in range(rn//24):
        off,info,add=struct.unpack_from('<QQq',raw,rows[2][4]+24*i)
        index=info>>32
        if info&0xffffffff!=4 or add!=-4 or off>tn-4 or not 2<=index<len(symbols):raise ValueError('relocation shape')
        if symbols[index][0][1]!=16 or raw[64+off:68+off]!=bytes(4):raise ValueError('relocation target')
        if any(abs(off-old)<4 for old,_ in rels):raise ValueError('overlapping relocations')
        rels.append((off,symbols[index][1]))
    return raw[64:64+tn],rels
def reference_object(parts):
    if len(parts)!=61 or any(not p or len(p)>4194304 for p in parts):raise ValueError('original leaf bound')
    bodies=[];relocations=[]
    for i,p in enumerate(parts):
        body,rels=inspect_object(p)if OBJECT_MASK>>i&1 else(p,[])
        bodies.append(body);relocations.append(rels)
    ctx=bodies[ROLES.index('context')]
    for off in context.TABLE_HOLES.values():
        if ctx[off-3:off]!=b'\x48\x8d\x05'or ctx[off:off+4]!=bytes(4):raise ValueError('fixed table hole')
    out=bytearray(ELF_HEADER+BRIDGE);starts=[]
    for body in bodies:
        out.extend(bytes((-len(out))%16));starts.append(len(out));out.extend(body)
    textn=len(out)-64
    if textn>16777216:raise ValueError('original text bound')
    targets=[starts[ROLES.index('public')],starts[ROLES.index('context')],starts[ROLES.index('public')]+528,starts[ROLES.index('registry')]]
    for (_,off),target in zip(EXPORTS,targets):struct.pack_into('<i',out,64+off+1,target-(64+off+5))
    for role,hole in rank.HOLES.items():
        at=64+RANK_AT+hole;struct.pack_into('<i',out,at,starts[ROLES.index('rank_'+role)]-at-4)
    at=starts[ROLES.index('context')]
    for name,hole in context.TABLE_HOLES.items():
        target=64+RANK_AT if name=='rank'else starts[ROLES.index(name)]
        struct.pack_into('<i',out,at+hole,target-at-hole-4)
    out.extend(bytes((-len(out))%8));relat=len(out)
    for start,rels in zip(starts,relocations):
        for off,name in rels:out.extend(struct.pack('<QQq',start-64+off,((6+IMPORTS.index(name))<<32)|4,-4))
    symbols,strings,sections=fixed_metadata();symat=len(out);out.extend(symbols);strat=len(out);out.extend(strings)
    namesat=len(out);out.extend(base.SECTIONS);noteat=len(out);out.extend(bytes((-len(out))%8));sh=len(out);out.extend(sections)
    struct.pack_into('<Q',out,40,sh)
    for i,off,n in [(1,64,textn),(2,relat,symat-relat),(3,symat,len(symbols)),(4,strat,len(strings)),(5,namesat,len(base.SECTIONS)),(6,noteat,0)]:
        struct.pack_into('<QQ',out,sh+64*i+24,off,n)
    return bytes(out)
def source_program():
    symbols,strings,sections=fixed_metadata();functions=[];calls={}
    for name,raw in [('prefix',ELF_HEADER+BRIDGE),('symbols',symbols),('strings',strings),('names',base.SECTIONS),('sections',sections)]:
        calls[name],fn=base.emitters('bg_bundle_'+name,raw);functions.append(fn)
    source=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<8192:
        return 4294967294
    if length(s)<{HEADER} or uint(s,0,8)!={MAGIC} or uint(s,8,8)!=61:
        return 4294967295
    at={HEADER}
    i=0
    rels=0
    while i<61:
        n=uint(s,16+i*8,8)
        if n==0 or n>4194304 or at>length(s) or n>length(s)-at:
            return 4294967295
        write(w,i*8,at,8)
        write(w,512+i*8,at,8)
        write(w,1024+i*8,n,8)
        write(w,2560+i*8,0,8)
        if (({OBJECT_MASK}>>i)&1)!=0:
            if inspect(s,w,i,at,n)==0:
                return 4294967295
            rels=rels+get(w,2560+i*8)
        at=at+n
        i=i+1
    if at!=length(s):
        return 4294967295
    if fixed_holes(s,w)==0:
        return 4294967295
    at={64+len(BRIDGE)}
    i=0
    while i<61:
        at=(at+15)&18446744073709551600
        write(w,1536+i*8,at,8)
        at=at+get(w,1024+i*8)
        i=i+1
    if at-64>16777216:
        return 4294967295
    write(w,4608,at,8)
    at=(at+7)&18446744073709551608
    write(w,4616,at,8)
    at=at+rels*24
    write(w,4624,at,8)
    at=at+{len(symbols)}
    write(w,4632,at,8)
    at=at+{len(strings)}
    write(w,4640,at,8)
    at=at+{len(base.SECTIONS)}
    write(w,4648,at,8)
    at=(at+7)&18446744073709551608
    write(w,4656,at,8)
    if length(o)<at+448:
        return 4294967294
    write(w,4664,at+448,8)
    i=0
    while i<at+448:
        store(o,i,0)
        i=i+1
'''
    for name,at in [('prefix','0'),('symbols','get(w,4624)'),('strings','get(w,4632)'),('names','get(w,4640)'),('sections','get(w,4656)')]:
        for fn in calls[name]:source+=f'    {fn}(o,{at})\n'
    source+='''    sh=get(w,4656)
    write(o,40,sh,8)
    write(o,sh+88,64,8)
    write(o,sh+96,get(w,4608)-64,8)
    write(o,sh+152,get(w,4616),8)
    write(o,sh+160,get(w,4624)-get(w,4616),8)
    write(o,sh+216,get(w,4624),8)
'''
    source+=f'''    write(o,sh+224,{len(symbols)},8)
    write(o,sh+280,get(w,4632),8)
    write(o,sh+288,{len(strings)},8)
    write(o,sh+344,get(w,4640),8)
    write(o,sh+352,{len(base.SECTIONS)},8)
    write(o,sh+408,get(w,4648),8)
    i=0
    while i<61:
        copy(s,o,get(w,512+i*8),get(w,1536+i*8),get(w,1024+i*8))
        i=i+1
'''
    targets=[f"get(w,{1536+8*ROLES.index('public')})",f"get(w,{1536+8*ROLES.index('context')})",f"get(w,{1536+8*ROLES.index('public')})+528",f"get(w,{1536+8*ROLES.index('registry')})"]
    for (_,off),target in zip(EXPORTS,targets):source+=f'    write(o,{64+off+1},{target}-{64+off+5},4)\n'
    for role,hole in rank.HOLES.items():
        source+=f'    write(o,{64+RANK_AT+hole},get(w,{1536+8*ROLES.index("rank_"+role)})-{64+RANK_AT+hole+4},4)\n'
    source+=f'    context_at=get(w,{1536+8*ROLES.index("context")})\n'
    for name,hole in context.TABLE_HOLES.items():
        target=str(64+RANK_AT)if name=='rank'else f'get(w,{1536+8*ROLES.index(name)})'
        source+=f'    write(o,context_at+{hole},{target}-context_at-{hole+4},4)\n'
    source+='''    emit_relocations(s,o,w)
    return get(w,4664)

def fixed_holes(s:readbuf,w:mutbuf) -> u64:
'''
    source+=f'    if get(w,{1024+8*ROLES.index("context")})<{len(bytes.fromhex(context.CONFIG["bridge"]))} or get(w,{1024+8*ROLES.index("public")})<544:\n        return 0\n    at=get(w,{512+8*ROLES.index("context")})\n'
    for hole in context.TABLE_HOLES.values():
        source+=f'    if uint(s,at+{hole-3},3)!=363848 or uint(s,at+{hole},4)!=0:\n        return 0\n'
    source+='    return 1\n'
    source+=INSPECT
    # All section metadata is fixed; only offsets and sizes are input dependent.
    source+='\ndef section_shape(s:readbuf,at:u64,index:u64) -> u64:\n'
    for i,(name,kind,flags,link,info,align,extent)in enumerate([
      ('.text',1,6,0,0,16,0),('.rela.text',4,0,3,1,8,24),('.symtab',2,0,4,2,8,24),
      ('.strtab',3,0,0,0,1,0),('.shstrtab',3,0,0,0,1,0),('.note.GNU-stack',1,0,0,0,1,0)],1):
        source+=f'''    if index=={i}:
        if uint(s,at,8)!={base.SECTIONS.index(name.encode()+bytes([0]))+(kind<<32)} or uint(s,at+8,8)!={flags} or uint(s,at+16,8)!=0:
            return 0
        if uint(s,at+40,8)!={link+(info<<32)} or uint(s,at+48,8)!={align} or uint(s,at+56,8)!={extent}:
            return 0
        return 1
'''
    source+='    return 0\n\ndef section_names(s:readbuf,at:u64) -> u64:\n'
    for i in range(0,len(base.SECTIONS),8):
        b=base.SECTIONS[i:i+8];source+=f'    if uint(s,at+{i},{len(b)})!={int.from_bytes(b,"little")}:\n        return 0\n'
    source+='    return 1\n\ndef import_name(s:readbuf,at:u64,n:u64) -> u64:\n'
    for i,name in enumerate(IMPORTS,1):
        raw=name.encode()+b'\0';condition=' and '.join(f'uint(s,at+{j},{len(raw[j:j+8])})=={int.from_bytes(raw[j:j+8],"little")}'for j in range(0,len(raw),8))
        source+=f'    if n>={len(raw)} and {condition}:\n        return {i}\n'
    source+='    return 0\n'
    source=source.replace('SECTION_NAMES_N',str(len(base.SECTIONS)))
    return source+'\n'+'\n'.join(functions)+base.HELPERS
INSPECT=r'''
def inspect(s:readbuf,w:mutbuf,index:u64,at:u64,n:u64) -> u64:
    if n<512 or uint(s,at,8)!=282584257676671 or uint(s,at+8,8)!=0 or uint(s,at+16,8)!=4299030529:
        return 0
    if uint(s,at+24,8)!=0 or uint(s,at+32,8)!=0 or uint(s,at+48,8)!=274877906944 or uint(s,at+56,8)!=1407404952518656:
        return 0
    sh=uint(s,at+40,8)
    if sh>n-448 or sh+448!=n:
        return 0
    sh=at+sh
    if zeros(s,sh,64)==0:
        return 0
    i=1
    while i<7:
        if section_shape(s,sh+64*i,i)==0:
            return 0
        i=i+1
    tn=uint(s,sh+96,8)
    if uint(s,sh+88,8)!=64 or tn==0 or tn>4194304:
        return 0
    cursor=(64+tn+7)&18446744073709551608
    if cursor>n or zeros(s,at+64+tn,cursor-64-tn)==0:
        return 0
    i=2
    while i<6:
        p=sh+64*i
        size=uint(s,p+32,8)
        if uint(s,p+24,8)!=cursor or size>n-cursor:
            return 0
        cursor=cursor+size
        i=i+1
    if uint(s,sh+408,8)!=cursor or uint(s,sh+416,8)!=0 or ((cursor+7)&18446744073709551608)!=sh-at:
        return 0
    if zeros(s,at+cursor,sh-at-cursor)==0:
        return 0
    rn=uint(s,sh+160,8)
    sn=uint(s,sh+224,8)
    stn=uint(s,sh+288,8)
    if rn>6144 or sn<48 or sn>6144 or stn==0 or stn>65536:
        return 0
    rc=records24(rn)
    sc=records24(sn)
    if rc==18446744073709551615 or sc==18446744073709551615:
        return 0
    if uint(s,sh+352,8)!=SECTION_NAMES_N:
        return 0
    if section_names(s,at+uint(s,sh+344,8))==0:
        return 0
    sy=at+uint(s,sh+216,8)
    st=at+uint(s,sh+280,8)
    if zeros(s,sy,24)==0 or uint(s,sy+24,8)!=281487861612544 or zeros(s,sy+32,16)==0 or byte(s,st)!=0:
        return 0
    if check_symbols(s,sy,st,stn,tn,sc)==0:
        return 0
    rp=at+uint(s,sh+152,8)
    if check_relocations(s,at,tn,rp,rc,sy,sc)==0:
        return 0
    write(w,512+index*8,at+64,8)
    write(w,1024+index*8,tn,8)
    write(w,2048+index*8,rp,8)
    write(w,2560+index*8,rc,8)
    write(w,3072+index*8,sy,8)
    write(w,3584+index*8,st,8)
    write(w,4096+index*8,stn,8)
    return 1

def check_symbols(s:readbuf,sy:u64,st:u64,stn:u64,tn:u64,sc:u64) -> u64:
    i=2
    while i<sc:
        p=sy+i*24
        name=uint(s,p,4)
        info=byte(s,p+4)
        value=uint(s,p+8,8)
        size=uint(s,p+16,8)
        if name==0 or name>=stn or byte(s,p+5)!=0:
            return 0
        end=st+name
        while end<st+stn and byte(s,end)!=0:
            end=end+1
        if end==st+stn:
            return 0
        if info==16:
            if uint(s,p+6,2)!=0 or value!=0 or size!=0 or import_name(s,st+name,stn-name)==0:
                return 0
        elif info==18:
            if uint(s,p+6,2)!=1 or value>tn or size>tn-value:
                return 0
        else:
            return 0
        i=i+1
    return 1

def check_relocations(s:readbuf,at:u64,tn:u64,rp:u64,rc:u64,sy:u64,sc:u64) -> u64:
    i=0
    while i<rc:
        p=rp+i*24
        off=uint(s,p,8)
        info=uint(s,p+8,8)
        si=info>>32
        if (info&4294967295)!=4 or uint(s,p+16,8)!=18446744073709551612 or tn<4 or off>tn-4 or si<2 or si>=sc:
            return 0
        if byte(s,sy+si*24+4)!=16 or uint(s,at+64+off,4)!=0:
            return 0
        j=0
        while j<i:
            before=uint(s,rp+j*24,8)
            if off<before+4 and before<off+4:
                return 0
            j=j+1
        i=i+1
    return 1

def records24(n:u64) -> u64:
    count=0
    while n>=24:
        n=n-24
        count=count+1
    if n!=0:
        return 18446744073709551615
    return count

def emit_relocations(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    target=get(w,4616)
    i=0
    while i<61:
        j=0
        while j<get(w,2560+i*8):
            p=get(w,2048+i*8)+24*j
            info=uint(s,p+8,8)
            sym=get(w,3072+i*8)+(info>>32)*24
            name=uint(s,sym,4)
            number=import_name(s,get(w,3584+i*8)+name,get(w,4096+i*8)-name)
            write(o,target,get(w,1536+i*8)-64+uint(s,p,8),8)
            write(o,target+8,((number+5)<<32)|4,8)
            write(o,target+16,18446744073709551612,8)
            target=target+24
            j=j+1
        i=i+1
    return 0

def zeros(s:readbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        if byte(s,at+i)!=0:
            return 0
        i=i+1
    return 1

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(i*8))
        i=i+1
    return value
'''
def main():
    name='background_optimizer_native_bundle_packer'
    d=document(source_program(),name);p=ROOT/'examples/hia_bootstrap'/(name+'.hepta')
    p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),
      sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
