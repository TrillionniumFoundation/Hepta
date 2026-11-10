"""Whole-byte emission, real short-capacity traps and unchanged private state."""
import ast
from pathlib import Path
import platform
import shutil
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program,render_assembly
from hepta.hia_program import execute_program
from hepta.hia_program_runtime import HIAProgramTrap,_Machine,_Owner,_View
from tools.generate_hia_selfhost import Builder,source_program
from tools.hia_selfhost_bulk import Body

# Exact previous finite Core authoring function, not a retained high-level
# frontend. Its recursive byte writes are the independent unchanged baseline.
PREVIOUS='''def emit_bytes(o:mutbuf, w:mutbuf, x:u64, remaining:u64) -> u64:
    if remaining == 0:
        return 0
    emit(o, w, x & 255)
    return emit_bytes(o, w, x >> 8, remaining - 1)
'''
ENTRY='''def probe(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = byte(s, 0)
    remaining = byte(s, 1)
    pos = byte(s, 2)
    x = byte(s, 3)
    x = x | (byte(s, 4) << 8)
    x = x | (byte(s, 5) << 16)
    x = x | (byte(s, 6) << 24)
    x = x | (byte(s, 7) << 32)
    x = x | (byte(s, 8) << 40)
    x = x | (byte(s, 9) << 48)
    x = x | (byte(s, 10) << 56)
    store(w, 48, phase)
    state_put32(w, 56, pos)
    emit_bytes(o, w, x, remaining)
    return state_get32(w, 56)
'''

def programs():
    all_nodes={n.name:n for n in ast.parse(source_program()).body}
    result={}
    for variant in ('previous','candidate'):
        nodes=[ast.parse(ENTRY).body[0]]+[all_nodes[n] for n in ('emit','emit_bytes','state_get32','state_put32')]
        if variant=='previous':nodes[2]=ast.parse(PREVIOUS).body[0]
        names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
        signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
        functions=[]
        for n in nodes:
            b=Builder(n,names,signatures);b.statements(n.body)
            functions.append(dict(name=names[n.name],params=[b.param(v) for v in b.params],
                returns=[b.returns],effects=['read','write','trap'],entry='b0',blocks=b.blocks))
        doc=dict(schema='hepta.hia.program.v8',module='emitter_words',functions=functions)
        source=render_assembly(doc).encode();assemble_program(source);result[variant]=source
    return result

def cases():
    for phase in (0,1,2):
        for count in (0,1,4,8):
            for position in (0,1,7):
                for capacity in (0,1,3,4,7,8,12):
                    value=0xfedcba9876543210
                    yield dict(phase=phase,count=count,position=position,capacity=capacity,
                        input=bytes([phase,count,position])+value.to_bytes(8,'little'),value=value)
    for value in (0,(1<<32)-1,1<<32,(1<<64)-1):
        yield dict(phase=2,count=8,position=1,capacity=12,
            input=bytes([2,8,1])+value.to_bytes(8,'little'),value=value)

def expectation(row):
    output=bytearray(b'\xa5'*row['capacity']);trapped=False;counter=row['position']
    if row['phase']==2:
        for i in range(row['count']):
            if row['position']+i>=len(output):trapped=True;break
            output[row['position']+i]=(row['value']>>(i*8))&255
            counter+=1
    if row['phase']==1:counter+=row['count']
    return trapped,bytes(output),counter

def vm_source(source,row):
    b=Body(0);owners=[];views=[]
    for initial in (row['input'],b'\xa5'*row['capacity'],bytes(256)):
        owner=b.value('buffer','buffer.new',[b.const('usize',len(initial))])
        view=b.value('mutbuf','borrow.mut',[owner])
        for i,value in enumerate(initial):
            if value:b.effect('buffer.store',[view,b.const('usize',i),b.const('u8',value)])
        owners.append(owner);views.append(view)
    b.effect('loan.end',[views[0]]);views[0]=b.value('readbuf','borrow.read',[owners[0]])
    result=b.value('u32','call',views,{'function':'f0'})
    values=[result]+[b.value('u8','buffer.load',[views[1],b.const('usize',i)]) for i in range(row['capacity'])]
    for view in views:b.effect('loan.end',[view])
    for owner in owners:b.effect('owner.drop',[owner])
    return ('hia-asm.v1 hepta.hia.program.v8 emitter_reference\nfn reference_entry() -> ('
        +','.join(['u32']+['u8']*row['capacity'])+') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
        +b.text()+'  ret('+','.join(values)+')\nend\n'+source.decode().split('\n',1)[1]).encode()

def independent_reference():
    sources=programs();observations=[]
    checked={variant:assemble_program(source) for variant,source in sources.items()}
    for row in cases():
        trapped,output,counter=expectation(row)
        for variant,program in checked.items():
            # Privileged independent byte-ABI oracle, as in the original trap
            # witnesses. Public interpreter callers still cannot invent views.
            machine=_Machine(program,1_000_000,16<<20,None,256)
            roots=[_Owner(-1,bytearray(row['input'])),_Owner(-2,bytearray(b'\xa5'*row['capacity'])),_Owner(-3,bytearray(256))]
            args=[_View(roots[0],False),_View(roots[1],True),_View(roots[2],True)]
            entry=next(fn for fn in program.as_dict()['functions'] if fn['name']=='f0')
            try:
                result=machine.invoke(entry,args)
            except HIAProgramTrap as exc:
                assert trapped and exc.code=='bounds',(row,variant,exc)
            else:
                assert not trapped and result==[counter],(row,variant,result)
            assert bytes(roots[0].data)==row['input']
            assert bytes(roots[1].data)==output,(row,variant)
            workspace=bytearray(256);workspace[48]=row['phase'];workspace[56:64]=counter.to_bytes(8,'little')
            assert roots[2].data==workspace,(row,variant)
        observations.append(dict(phase=row['phase'],count=row['count'],position=row['position'],
            capacity=row['capacity'],value=row['value'],trapped=trapped,expected_output_hex=output.hex(),expected_counter=counter))
    return sources,observations

class EmitterSourceTests(unittest.TestCase):
    def test_all_phases_capacities_and_full_width_words_match_independent_Core_VM(self):
        _,observations=independent_reference()
        self.assertEqual(len(observations),256)
        self.assertTrue(any(row['trapped'] for row in observations))

    def test_public_VM_wrappers_retain_resources_and_full_emission_results(self):
        rows=[row for row in cases() if not expectation(row)[0]][::23]
        for source in programs().values():
            for row in rows:
                _,output,counter=expectation(row)
                result=execute_program(assemble_program(vm_source(source,row)),'reference_entry',[])
                self.assertEqual(result['values'],[counter,*output])
                self.assertEqual(result['resources']['live_owners'],0)
                self.assertEqual(result['resources']['live_local_loans'],0)

@unittest.skipUnless(platform.system()=='Linux' and platform.machine().lower() in ('x86_64','amd64')
    and shutil.which('ld'),'Linux x86-64 native bootstrap required')
class EmitterNativeTests(unittest.TestCase):
    def test_actual_prefix_writes_counter_and_real_traps_match_the_unchanged_emitter(self):
        from tools.qualify_hia_selfhost import build_seed,compile_stage,invoke,SOURCE
        sources,observations=independent_reference() # before any seed exists
        with tempfile.TemporaryDirectory(prefix='hia-emitter-words-') as name:
            root=Path(name);seed,_=build_seed(root)
            compiler,_=compile_stage(root,'B1',seed,SOURCE.read_bytes(),image_format='seed-shared')
            images={key:compile_stage(root,key,compiler,source)[0] for key,source in sources.items()}
            for i,(row,expected) in enumerate(zip(cases(),observations,strict=True)):
                paired=[]
                for variant,image in images.items():
                    actual,output=invoke(root,str(i)+'-'+variant,image,row['input'],capacity=row['capacity'],
                        workspace_size=256,workspace_fill=0,observe_trap_writes=True)
                    self.assertEqual(output.hex(),expected['expected_output_hex'],(i,variant))
                    if expected['trapped']:
                        self.assertEqual((actual['status'],actual['returncode']),('child_failed',-4))
                    else:
                        self.assertEqual((actual['status'],actual['core_u32']),('returned',expected['expected_counter']))
                        self.assertEqual(actual['workspace_header']['56'],expected['expected_counter'])
                    paired.append((actual['status'],output))
                self.assertEqual(paired[0],paired[1])
            self.case_counts={'independent_VM_observations':512,'actual_native_observations':512,
                'word_capacity_phase_cases':256,'fresh_seed_after_VM':True}

if __name__=='__main__':unittest.main()
