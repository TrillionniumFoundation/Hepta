"""Regenerate the Store's ENOSYS path transport and exact native packer literals.

The HIA packers keep their original admission CFG and all non-geometric operations.
Only the checked adapter prefix, its lengths/relocations, and binding metadata change.
No old checkout, compiled artifact, host linker or private QA path is an input.
"""
from pathlib import Path
from hashlib import sha256
from tempfile import TemporaryDirectory
import argparse,copy,json,struct
from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import assemble_adapter
from tools.generate_hia_native_filter import assemble_program,elf_header,bind_adapter,_binding_declaration

ROOT=Path(__file__).resolve().parents[1]
COMMON='tools/hia_open_nofollow.S'
MARKER='/* BEGIN HIA_OPEN_NOFOLLOW_GENERATED */'
PROFILES=(
 ('tools/hia_agent_store_init_syscalls.S','examples/hia_bootstrap/agent_store/namespace_init_packer.hepta',
  ('f1','f2','f3'),{'f5':8,'f6':4},('policy_call_hole',)),
 ('tools/hia_agent_store_syscalls.S','examples/hia_bootstrap/agent_store/packer.hepta',
  tuple('f'+str(i) for i in range(4,20)),{'f2':8,'f3':4},
  ('loader_call_hole','owner_call_hole','manifest_address_hole','json_call_hole')),
)

def transport(source,common):
    before=source.partition(MARKER)[0].rstrip()+'\n'
    old=' mov eax,437\n syscall\n'
    new=' call .Lhia_open_nofollow_entry\n nop\n nop\n'
    if old in before:
        assert before.count(old)==2 and new not in before
        before=before.replace(old,new)
    assert before.count(new)==2 and old not in before
    return before+'\n'+MARKER+'\n'+common

def binding_record(document,calls):
    records=[f for f in document['functions'] if f['name']=='adapter_binding']
    assert len(records)==1
    record=records[0]
    words=tuple(op['attrs']['value'] for op in record['blocks'][0]['ops'])
    assert record==_binding_declaration(words)
    payload=struct.pack('<'+str(9+calls)+'Q',*words)
    source,adapter,size,*holes=struct.unpack('<32s32s'+str(1+calls)+'Q',payload)
    assert 0<size<1<<20 and len(set(holes))==calls and all(0<h<=size-4 for h in holes)
    return source,adapter,size,tuple(holes)

def literal_prefix(document,names,writers,size,holes,adapter_digest):
    length=(len(elf_header())+size+7)//8*8
    prefix=bytearray(length);seen=bytearray(length)
    for function in document['functions']:
        if function['name'] not in names:continue
        assert len(function['blocks'])==1
        ops=function['blocks'][0]['ops']
        constants={}
        for op in ops:
            if op['op']=='const':
                constants[op['out'][0]['name']]=op['attrs']['value']
                continue
            assert op['op']=='call' and op['attrs']['function'] in writers
            assert len(op['args'])==3 and op['args'][0]=='v0'
            at=constants[op['args'][1]];value=constants[op['args'][2]]
            width=writers[op['attrs']['function']]
            assert 0<=at<=length-width and not any(seen[at:at+width])
            prefix[at:at+width]=value.to_bytes(width,'little')
            seen[at:at+width]=bytes([1])*width
    assert prefix[:len(elf_header())]==elf_header() and not any(prefix[len(elf_header())+size:])
    unbound=bytearray(prefix[len(elf_header()):len(elf_header())+size])
    prebound=[]
    for hole in holes:
        absolute=len(elf_header())+hole
        value=int.from_bytes(prefix[absolute:absolute+4],'little')
        assert value in [0,length-absolute-4],(hole,value,length)
        prebound.append(bool(value))
        unbound[hole:hole+4]=bytes(4)
    assert sha256(unbound).digest()==adapter_digest,'previous literal adapter does not match its own native binding'
    return bytes(prefix),prebound

def literal_function(old,words,writer):
    function=copy.deepcopy(old)
    assert function['params']==[{'name':'v0','type':'mutbuf'}]
    ops=[{'op':'const','args':[],'attrs':{'value':0},'out':[{'name':'v1','type':'u64'}]}]
    number=2
    for at,value in words:
        left,right,result=('v'+str(number+i) for i in range(3));number+=3
        ops.extend([
         {'op':'const','args':[],'attrs':{'value':at},'out':[{'name':left,'type':'u64'}]},
         {'op':'const','args':[],'attrs':{'value':value},'out':[{'name':right,'type':'u64'}]},
         {'op':'call','args':['v0',left,right],'attrs':{'function':writer},'out':[{'name':result,'type':'u64'}]}])
    function['blocks']=[{'id':function['entry'],'params':function['params'],'ops':ops,'term':{'op':'ret','values':['v1']}}]
    return function

def rebind(packer,source,stub,symbols,names,writers,call_symbols):
    doc=assemble_program(packer).as_dict()
    oldsource,oldadapter,oldsize,oldholes=binding_record(doc,len(call_symbols))
    oldprefix,prebound=literal_prefix(doc,names,writers,oldsize,oldholes,oldadapter)
    holes=tuple(symbols[n] for n in call_symbols)
    assert holes==oldholes,'the syscall replacement must preserve all prior embedded owner call sites'
    prefix=bytearray(elf_header()+stub);prefix+=bytes((-len(prefix))%8)
    for hole,was_bound in zip(holes,prebound,strict=True):
        if was_bound:struct.pack_into('<I',prefix,len(elf_header())+hole,len(prefix)-len(elf_header())-hole-4)
    mapping={len(oldprefix):len(prefix)}
    for hole in holes:
        mapping[len(oldprefix)-len(elf_header())-hole-4]=len(prefix)-len(elf_header())-hole-4
    changed=[]
    entry=doc['functions'][0]
    assert entry['name']=='f0'
    for block in entry['blocks']:
        for op in block['ops']:
            if op['op']=='const' and op['attrs']['value'] in mapping:
                before=op['attrs']['value'];after=mapping[before];op['attrs']['value']=after
                changed.append({'block':block['id'],'before':before,'after':after})
    assert sum(x['before']==len(oldprefix) for x in changed)>=3
    words=[(at,int.from_bytes(prefix[at:at+8],'little')) for at in range(0,len(prefix),8)]
    span=(len(words)+len(names)-1)//len(names)
    writer=next(name for name,width in writers.items() if width==8)
    updated={}
    for index,name in enumerate(names):
        original=next(f for f in doc['functions'] if f['name']==name)
        updated[name]=literal_function(original,words[index*span:(index+1)*span],writer)
    doc['functions']=[updated.get(f['name'],f) for f in doc['functions'] if f['name']!='adapter_binding']
    bind_adapter(doc,source,stub,holes)
    return render_assembly(doc),{'old_adapter_sha256':oldadapter.hex(),'adapter_sha256':sha256(stub).hexdigest(),
       'adapter_bytes':len(stub),'old_prefix_bytes':len(oldprefix),'prefix_bytes':len(prefix),'geometry':changed,
       'owner_call_holes':list(holes),'original_HIA_admission_and_non_geometry_operations_preserved':True}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',action='store_true');p.add_argument('--report',type=Path)
    args=p.parse_args()
    common=(ROOT/COMMON).read_text()
    rows=[]
    with TemporaryDirectory(prefix='hia-store-path-author-') as tmp:
        for index,(adapter,packer,names,writers,calls) in enumerate(PROFILES):
            existing=(ROOT/adapter).read_bytes()
            source=transport(existing.decode(),common).encode()
            work=Path(tmp)/str(index);work.mkdir()
            stub,symbols,_=assemble_adapter(work,Path(adapter).name,source)
            old=(ROOT/packer).read_bytes()
            rendered,row=rebind(old,source,stub,symbols,names,writers,calls)
            if args.check:
                assert source==existing,adapter+' transport is stale'
                assert rendered.encode()==old,packer+' packer is stale'
            else:
                (ROOT/adapter).write_bytes(source);(ROOT/packer).write_text(rendered)
            row.update(adapter=adapter,packer=packer,source_sha256=sha256(source).hexdigest(),packer_sha256=sha256(rendered.encode()).hexdigest())
            rows.append(row)
    result={'schema':'hia.store-path-transport-generation.v1','status':'passed','check':args.check,'profiles':rows}
    if args.report:args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result),flush=True)
if __name__=='__main__':main()
