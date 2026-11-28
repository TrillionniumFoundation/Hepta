"""Development author for the native post-cold source bootstrap entry.

The emitted HIA owns capture/verification. This variant preserves the qualified
pre-cold entry unchanged and adds only two separately captured cold-result assets.
"""
from pathlib import Path
from hashlib import sha256
import ast,struct,subprocess,tempfile
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_build_entry import source as base_source
from tools.generate_hia_cold_document import bulk_document as packer_document
from tools.hia_cold_guarded_write import bulk_document
from tools.generate_hia_native_filter import LINK_SOURCE

ROOT=Path(__file__).resolve().parents[1]
RECIPE=b'examples/hia_bootstrap/cold_source_bootstrap_recipe.hiadat'
OLD_RECIPE=b'examples/hia_bootstrap/cold_build_recipe.hiadat'
B3_PATH=b'qualification/base/B3.flat'
REPORT_PATH=b'final-cold.json'

ARGUMENTS=r'''def arguments(s:readbuf,w:mutbuf) -> u64:
    argc = uint(s,8,8)
    if argc != 9 and argc != 4:
        return 0
    put(w,2016,choose(argc == 4,1,0))
    at = 304
    i = 0
    while i < argc:
        if at > 65536-9:
            return 0
        n = uint(s,at,8)
        if n == 0 or n > 8191 or n > 65536-at-9 or byte(s,at+8+n) != 0:
            return 0
        if i != 0:
            if argc == 4:
                if i == 1:
                    if n != 10 or same_input(s,w,at+8,61424,10) == 0:
                        return 0
                else:
                    fd = decimal_input(s,at+8,n)
                    if fd == 0:
                        return 0
                    put(w,choose(i == 2,2064,2056),fd)
            elif i & 1 != 0:
                tag = choose(i == 1,62000,choose(i == 3,62048,choose(i == 5,62016,62032)))
                size = choose(i == 3,6,choose(i == 5,11,8))
                if n != size or same_input(s,w,at+8,tag,size) == 0:
                    return 0
            else:
                target = choose(i == 2,320000,choose(i == 4,370000,choose(i == 6,328192,336384)))
                stored = choose(i == 2,2800,choose(i == 4,2848,choose(i == 6,2808,2816)))
                if n < 2 or byte(s,at+8) != 47:
                    return 0
                copy_input(s,w,target,at+8,n+1)
                put(w,stored,n)
        at = at+9+n
        i = i+1
    return 1
'''

def replace_function(text,name,new):
    node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name)
    lines=text.splitlines();return '\n'.join(lines[:node.lineno-1]+new.strip().splitlines()+lines[node.end_lineno:])+'\n'

def source():
    text=base_source()
    # Two additional asset rows need 256 bytes. Shift the adjacent private tables
    # by 512 bytes, retaining their original counts and the 8 MiB total workspace.
    class ShiftTables(ast.NodeTransformer):
        def visit_FunctionDef(self,node):
            if node.name.startswith('constants'):return node
            return self.generic_visit(node)
        def visit_Constant(self,node):
            if type(node.value) is int and 6816768<=node.value<7177216:
                return ast.copy_location(ast.Constant(node.value+512),node)
            return node
    text=ast.unparse(ast.fix_missing_locations(ShiftTables().visit(ast.parse(text))))+'\n'
    text=replace_function(text,'arguments',ARGUMENTS)
    parsed=ast.parse(text)
    functions={n.name:ast.get_source_segment(text,n) for n in parsed.body if isinstance(n,ast.FunctionDef)}
    for name in ('source_manifest_add','valid_source_manifest'):
        text=replace_function(text,name,functions[name].replace('asset_row(i + 8)','asset_row(i + 10)'))
    for name in ('capture_all','postverify','valid_transport','inner_start'):
        part=functions[name].replace('get(w, 2096) + 8','get(w, 2096) + 10')
        part=part.replace('get(w, 2880) + 8','get(w, 2880) + 10').replace('get(w, 2888) + 8','get(w, 2888) + 10')
        if name=='capture_all':
            part=part.replace('get(w, 2400) < 8','get(w, 2400) < 10').replace('get(w, 2400) >= 8','get(w, 2400) >= 10').replace('get(w, 2400) - 8','get(w, 2400) - 10')
        if name=='inner_start':part=part.replace('get(w, 2400) == 8','get(w, 2400) == 10')
        if name=='valid_transport':
            part=part.replace('if i == 7 and (n == 0 or n > 1048576):','if (i == 7 or i == 8) and (n == 0 or n > 1048576):')
            part=part.replace('        at = at + n','        if i == 9 and n == 0:\n            return 0\n        at = at + n')
        text=replace_function(text,name,part)
    for name in ('driver_frame','run_stage'):
        text=replace_function(text,name,functions[name].replace('get(w, row + 8) + 8','get(w, row + 8) + 10'))
    part=functions['begin_source_capture'].replace('index = i - 8','''if i == 8:
        return start_capture(s,o,w,63800,@B3_SIZE@,get(w,2896),1048576,256,0,0,after)
    if i == 9:
        return start_capture(s,o,w,63900,@REPORT_SIZE@,get(w,2896),67108864,256,0,0,after)
    index = i - 10''').replace('@B3_SIZE@',str(len(B3_PATH))).replace('@REPORT_SIZE@',str(len(REPORT_PATH)))
    text=replace_function(text,'begin_source_capture',part)
    part=functions['startup'].replace('constants(w)','constants(w)\n        post_constants(w)')
    part=part.replace('return open_path(s, o, w, 328192, get(w, 2808), 18446744073709551516, 0, 4)','''return open_path(s,o,w,370000,get(w,2848),18446744073709551516,0,9)
    if p == 9:
        put(w,2896,get(w,2592))
        return open_path(s,o,w,328192,get(w,2808),18446744073709551516,0,4)''')
    text=replace_function(text,'startup',part)
    part=functions['begin_binding'].replace('index + 8','index + 10')
    part=part.replace('    if kind == 2:', '''    if kind == 6 or kind == 7:
        row = asset_row(kind+2)
        return start_extract(o,w,get(w,2064),get(w,row),get(w,row+8),row+16,after)
    if kind == 2:''')
    text=replace_function(text,'begin_binding',part)
    text=replace_function(text,'valid_stage',functions['valid_stage'].replace('kind > 5','kind > 7'))
    text=replace_function(text,'owner_request',functions['owner_request'].replace('argument(w, 400128, 61000, 14)','argument(w, 400128, 61000, 20)'))
    # The post recipe still uses HIATBR01. Only this independent capsule accepts
    # cold-result kinds 6/7; its sealed transport and receipts are distinct.
    for old,new in ((b'HIATBX01',b'HIASBX01'),(b'HIATBOK1',b'HIASBOK1'),(b'HIATBIK1',b'HIASBIK1')):
        text=text.replace(str(int.from_bytes(old,'little')),str(int.from_bytes(new,'little')))
    text=text.replace('size == '+str(len(OLD_RECIPE))+' and same(w, path, 61632, size)', 'size == '+str(len(RECIPE))+' and same(w, path, 61632, size)')
    text=text.replace('w, 61632, '+str(len(OLD_RECIPE))+', get(w, 2040)', 'w, 61632, '+str(len(RECIPE))+', get(w, 2040)')
    items=[(61000,b'hia-source-bootstrap\0'),(61632,RECIPE+b'\0'),(62048,b'--cold\0'),(63800,B3_PATH+b'\0'),(63900,REPORT_PATH+b'\0')]
    text+='\ndef post_constants(w:mutbuf) -> u64:\n    fill_range(w,61000,32,0)\n    fill_range(w,61632,128,0)\n'
    for at,raw in items:
        for off in range(0,len(raw),8):text+=f'    put(w,{at+off},{int.from_bytes(raw[off:off+8],"little")})\n'
    text+='    return 0\n'
    # These numeric/header guards only read validated private-table domains.
    # Eager predicates preserve their complete result and original limits.
    class HeaderPredicates(ast.NodeTransformer):
        def __init__(self,minimum):self.minimum=minimum
        def visit_BoolOp(self,node):
            node=self.generic_visit(node)
            if not isinstance(node.op,ast.Or) or len(node.values)<self.minimum:return node
            terms=[ast.Call(func=ast.Name(id='choose',ctx=ast.Load()),args=[v,ast.Constant(1),ast.Constant(0)],keywords=[]) for v in node.values]
            value=terms[0]
            for term in terms[1:]:value=ast.BinOp(left=value,op=ast.BitOr(),right=term)
            return ast.Compare(left=value,ops=[ast.NotEq()],comparators=[ast.Constant(0)])
    for name,minimum in (('valid_recipe',2),('valid_authority',5)):
        node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name)
        text=replace_function(text,name,ast.unparse(ast.fix_missing_locations(HeaderPredicates(minimum).visit(node))))
    assert 'asset_row(i + 8)' not in text
    assert 'get(w, 2096) + 8' not in text
    assert 'get(w, row + 8) + 8' not in text
    return text

def template():
    with tempfile.TemporaryDirectory(prefix='hia-source-bootstrap-author-') as tmp:
        obj=Path(tmp)/'a.o';raw=Path(tmp)/'a.bin'
        subprocess.run(['as','--64',str(ROOT/'tools/hia_cold_build_entry_syscalls.S'),'-o',str(obj)],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
        symbols={name:int(addr,16) for addr,_,name in (line.split() for line in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines())}
        assert symbols['_start']==0 and 'R_X86_64' not in subprocess.check_output(['objdump','-r',str(obj)],text=True)
        code=raw.read_bytes()
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)+struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    return header+code,{n:176+symbols[n] for n in ('policy_hole','sha_hole','entry_pins')}

def packer():
    prefix,holes=template()
    text=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 314 or uint(s,0,8) != {int.from_bytes(b'HIASBP01','little')}:
        return 4294967295
    policy = uint(s,8,8)
    sha = uint(s,16,8)
    if policy == 0 or sha == 0 or policy > 1048576 or sha > 1048576 or length(s) != 312+policy+sha:
        return 4294967295
    i = 24
    while i < 312:
        if uint(s,i,8) | uint(s,i+8,8) | uint(s,i+16,8) | uint(s,i+24,8) == 0:
            return 4294967295
        i = i+32
    size = {len(prefix)}+policy+sha
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for at in range(0,len(prefix),8):
        raw=prefix[at:at+8];text+=f'    write(o,{at},{int.from_bytes(raw,"little")},{len(raw)})\n'
    text+=f'''    write(o,96,size,8)
    write(o,104,size,8)
    write(o,{holes['policy_hole']},{len(prefix)-holes['policy_hole']-4},4)
    write(o,{holes['sha_hole']},{len(prefix)-holes['sha_hole']-4}+policy,4)
    copy_bytes(s,o,24,{holes['entry_pins']},288)
    copy_bytes(s,o,312,{len(prefix)},policy+sha)
    return size
'''
    return text+LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]

if __name__=='__main__':
    for name,text in [('cold_source_bootstrap_entry',source()),('cold_source_bootstrap_entry_packer',packer())]:
        doc=bulk_document(text,name) if name == 'cold_source_bootstrap_entry' else packer_document(text,name);raw=render_assembly(doc).encode();(ROOT/'examples/hia_bootstrap'/(name+'.hepta')).write_bytes(raw)
        print(name,len(raw),len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),max(len(f['blocks']) for f in doc['functions']),sha256(raw).hexdigest(),flush=True)
