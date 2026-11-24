"""Author the source-bound Worker identity map and hexadecimal byte encoder."""
from pathlib import Path
from hashlib import sha256
import argparse,ast,json,struct
from tools.generate_hia_worker_install_bind import SOURCE as HELPERS,sha_functions
from tools.generate_hia_direct_load_plan import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
TABLE='examples/hia_bootstrap/worker_install_identity_paths.hiastd'
SOURCE=r'''def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 2097152 or length(o) < 33554432:
        return 17
    phase = get(w, 0)
    mode = get(w, 16)
    if phase == 0 and mode == 0:
        if length(s) != 21 or uint(s, 0) != 1 or uint(s, 8) != 5 or uintn(s, 16, 5) != 431315580258:
            return 16
        put(w, 16, 1)
        return 0
    if phase == 2 and mode == 3:
        return 3
    if phase != 1 or mode != 1 or length(s) < 32 or length(s) > 2097152 or uint(s, 0) != MAGIC:
        return 16
    selected = uint(s, 8)
    put(w, 256, 0)
    if selected == 2:
        if uint(s, 16) != 1 or uint(s, 24) > 65536 or 32 + uint(s, 24) != length(s):
            return 16
        hex_input(s, o, w, 32, uint(s, 24))
    elif selected == 1:
        if uint(s, 16) != 2 or map_identity(s, o, w) == 0:
            return 16
    else:
        return 16
    put(w, 0, 1)
    put(w, 16, 3)
    put(w, 88, get(w, 256))
    return 0

def map_identity(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = uint(s, 24)
    if size < 16 or size > 1048576 or 40 + size > length(s):
        return 0
    table = 40 + size
    if uint(s, table - 8) != TABLE_BYTES or table + TABLE_BYTES != length(s):
        return 0
    digest(s, o, w, table, TABLE_BYTES, 16777216)
    constants(w)
    i = 0
    while i < 32:
        if byte(o, 16777216 + i) != byte(w, 16384 + i):
            return 0
        i = i + 1
    if uint(s, 32) != SPI_MAGIC or uint(s, 40) == 0 or uint(s, 40) > 4096:
        return 0
    put(w, 288, 32 + size)
    put(w, 296, 48)
    put(w, 304, 0)
    at = table + 16
    output_byte(o, w, 123)
    i = 0
    while i < TABLE_COUNT:
        count = uint(s, at)
        at = at + 8
        pin = find_pin(s, w, at, count)
        if pin == 0:
            return 0
        if i != 0:
            output_byte(o, w, 44)
        output_byte(o, w, 34)
        emit(s, o, w, at, count)
        output_byte(o, w, 34)
        output_byte(o, w, 58)
        output_byte(o, w, 34)
        hex_input(s, o, w, pin, 32)
        output_byte(o, w, 34)
        at = at + count
        i = i + 1
    output_byte(o, w, 125)
    if at != length(s):
        return 0
    while get(w, 304) < uint(s, 40):
        if next_pin(s, w) == 0:
            return 0
    if get(w, 296) != get(w, 288):
        return 0
    digest_mut(o, w, 0, get(w, 256), 16777216)
    i = 0
    while i < 32:
        store(o, i, byte(o, 16777216 + i))
        i = i + 1
    put(w, 256, 32)
    return 1

def next_pin(s:readbuf, w:mutbuf) -> u64:
    at = get(w, 296)
    end = get(w, 288)
    if at > end or end - at < 41 or get(w, 304) >= uint(s, 40):
        return 0
    n = uint(s, at)
    if n == 0 or n > 4095 or n > end - at - 40:
        return 0
    i = 0
    while i < n:
        ch = byte(s, at + 40 + i)
        if ch < 32 or ch > 126 or ch == 34 or ch == 92:
            return 0
        i = i + 1
    if get(w, 304) != 0:
        previous = get(w, 312)
        if compare(s, previous + 40, uint(s, previous), at + 40, n) != 1:
            return 0
    put(w, 312, at)
    put(w, 296, at + 40 + n)
    put(w, 304, get(w, 304) + 1)
    return at

def find_pin(s:readbuf, w:mutbuf, name:u64, size:u64) -> u64:
    while get(w, 304) < uint(s, 40):
        row = next_pin(s, w)
        if row == 0:
            return 0
        order = compare(s, row + 40, uint(s, row), name, size)
        if order == 0:
            return row + 8
        if order == 2:
            return 0
    return 0

def compare(s:readbuf, a:u64, an:u64, b:u64, bn:u64) -> u64:
    i = 0
    while i < an and i < bn:
        if byte(s, a + i) < byte(s, b + i):
            return 1
        if byte(s, a + i) > byte(s, b + i):
            return 2
        i = i + 1
    return choose(an == bn, 0, choose(an < bn, 1, 2))
'''
def paths():
    from hepta import hia_agent_contract as c
    result={str(p.relative_to(ROOT)) for p in (ROOT/'hepta').rglob('*.py') if p.relative_to(ROOT/'hepta').parts[0]!='_data'}
    result.update('docs/'+n for n in c.DISCOVERY_FILES)
    for key in ('NATIVE_SOURCE_FILES','SOURCE_BUILD_FILES','COMPILER_BUILD_FILES','PUBLICATION_BUILD_FILES','BACKEND_BUILD_FILES','EMITTER_BUILD_FILES','BYTE_WRAPPER_BUILD_FILES','MACHINE_OBJECT_BUILD_FILES','EXECUTION_OBSERVATION_BUILD_FILES','CONTINUATION_BUILD_FILES'):result.update(getattr(c,key))
    return tuple(sorted(result))
def table_bytes():
    names=paths();return b'HIAWIS01'+struct.pack('<Q',len(names))+b''.join(struct.pack('<Q',len(p.encode()))+p.encode() for p in names)
def policy_source(raw):
    names=('put','get','uint','uintn','copy','emit','output_byte','hex_input','hex_digit','same')
    helpers='\n'.join(ast.get_source_segment(HELPERS,n) for n in ast.parse(HELPERS).body if n.name in names)
    s=SOURCE.replace('TABLE_BYTES',str(len(raw))).replace('TABLE_COUNT',str(len(paths()))).replace('SPI_MAGIC',str(int.from_bytes(b'HIASPI01','little'))).replace('MAGIC',str(int.from_bytes(b'HIAWID01','little')))
    s+='\n'+helpers+'\n'+sha_functions()+'\ndef constants(w:mutbuf) -> u64:\n'
    pin=sha256(raw).digest()
    for i in range(0,32,8):s+='    put(w, %d, %d)\n'%(16384+i,int.from_bytes(pin[i:i+8],'little'))
    return s+'    return 0\n'
def document(source,module):
    nodes=ast.parse(source).body;names={n.name:'f'+str(i) for i,n in enumerate(nodes)};sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes};total=total_scalar_functions(nodes);fns=[]
    for n in nodes:
        b=LinkerBuilder(n,names,sigs,total);b.statements(n.body);fns.append({'name':names[n.name],'params':[b.param(a) for a in b.params],'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':module,'functions':fns})
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',action='store_true');a=p.parse_args();raw=table_bytes();doc=document(policy_source(raw),'source_worker_install_identity');source=render_assembly(doc).encode()
    for name,value in ((TABLE,raw),('examples/hia_bootstrap/source_worker_install_identity.hepta',source)):
        target=ROOT/name
        if a.check:
            if target.read_bytes()!=value:raise SystemExit(name+' differs')
        else:target.write_bytes(value)
        print(json.dumps({'name':name,'bytes':len(value),'sha256':sha256(value).hexdigest()}))
    print('functions',len(doc['functions']),'maxCFG',max(len(b['params']) for f in doc['functions'] for b in f['blocks']))
if __name__=='__main__':main()
